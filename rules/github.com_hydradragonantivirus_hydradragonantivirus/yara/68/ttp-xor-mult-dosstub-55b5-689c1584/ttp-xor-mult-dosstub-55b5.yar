rule TTP_XOR_MULT_DOSStub_55b5 {
  strings:
    $key_55b5 = { 01 dd [2] 75 c5 [2] 32 c7 [2] 75 d6 [2] 3b da [2] 37 d0 [2] 20 db [2] 3b 95 [2] 06 }

  condition:
    any of them
}