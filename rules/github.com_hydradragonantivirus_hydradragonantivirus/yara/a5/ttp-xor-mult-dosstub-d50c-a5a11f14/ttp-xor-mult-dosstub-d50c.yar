rule TTP_XOR_MULT_DOSStub_d50c {
  strings:
    $key_d50c = { 81 64 [2] f5 7c [2] b2 7e [2] f5 6f [2] bb 63 [2] b7 69 [2] a0 62 [2] bb 2c [2] 86 }

  condition:
    any of them
}