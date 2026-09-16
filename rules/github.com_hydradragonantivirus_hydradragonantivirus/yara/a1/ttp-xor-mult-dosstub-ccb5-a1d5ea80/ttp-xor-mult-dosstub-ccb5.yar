rule TTP_XOR_MULT_DOSStub_ccb5 {
  strings:
    $key_ccb5 = { 98 dd [2] ec c5 [2] ab c7 [2] ec d6 [2] a2 da [2] ae d0 [2] b9 db [2] a2 95 [2] 9f }

  condition:
    any of them
}