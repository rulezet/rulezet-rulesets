rule TTP_XOR_MULT_DOSStub_ccb1 {
  strings:
    $key_ccb1 = { 98 d9 [2] ec c1 [2] ab c3 [2] ec d2 [2] a2 de [2] ae d4 [2] b9 df [2] a2 91 [2] 9f }

  condition:
    any of them
}