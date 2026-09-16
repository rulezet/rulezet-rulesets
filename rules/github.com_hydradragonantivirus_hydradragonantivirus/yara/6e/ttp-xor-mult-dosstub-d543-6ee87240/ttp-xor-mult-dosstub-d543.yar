rule TTP_XOR_MULT_DOSStub_d543 {
  strings:
    $key_d543 = { 81 2b [2] f5 33 [2] b2 31 [2] f5 20 [2] bb 2c [2] b7 26 [2] a0 2d [2] bb 63 [2] 86 }

  condition:
    any of them
}