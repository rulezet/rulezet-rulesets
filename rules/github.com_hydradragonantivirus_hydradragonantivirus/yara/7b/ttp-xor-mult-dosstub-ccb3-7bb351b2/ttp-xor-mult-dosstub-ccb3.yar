rule TTP_XOR_MULT_DOSStub_ccb3 {
  strings:
    $key_ccb3 = { 98 db [2] ec c3 [2] ab c1 [2] ec d0 [2] a2 dc [2] ae d6 [2] b9 dd [2] a2 93 [2] 9f }

  condition:
    any of them
}