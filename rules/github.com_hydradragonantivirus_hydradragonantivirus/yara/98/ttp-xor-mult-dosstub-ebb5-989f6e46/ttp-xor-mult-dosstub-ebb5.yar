rule TTP_XOR_MULT_DOSStub_ebb5 {
  strings:
    $key_ebb5 = { bf dd [2] cb c5 [2] 8c c7 [2] cb d6 [2] 85 da [2] 89 d0 [2] 9e db [2] 85 95 [2] b8 }

  condition:
    any of them
}