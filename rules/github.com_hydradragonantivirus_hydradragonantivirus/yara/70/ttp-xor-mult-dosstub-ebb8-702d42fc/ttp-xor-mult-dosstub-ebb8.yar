rule TTP_XOR_MULT_DOSStub_ebb8 {
  strings:
    $key_ebb8 = { bf d0 [2] cb c8 [2] 8c ca [2] cb db [2] 85 d7 [2] 89 dd [2] 9e d6 [2] 85 98 [2] b8 }

  condition:
    any of them
}