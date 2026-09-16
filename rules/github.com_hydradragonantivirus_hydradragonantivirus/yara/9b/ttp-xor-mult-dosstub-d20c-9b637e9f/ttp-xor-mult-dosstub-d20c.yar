rule TTP_XOR_MULT_DOSStub_d20c {
  strings:
    $key_d20c = { 86 64 [2] f2 7c [2] b5 7e [2] f2 6f [2] bc 63 [2] b0 69 [2] a7 62 [2] bc 2c [2] 81 }

  condition:
    any of them
}