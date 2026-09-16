rule TTP_XOR_MULT_DOSStub_d521 {
  strings:
    $key_d521 = { 81 49 [2] f5 51 [2] b2 53 [2] f5 42 [2] bb 4e [2] b7 44 [2] a0 4f [2] bb 01 [2] 86 }

  condition:
    any of them
}