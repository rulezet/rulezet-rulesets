rule TTP_XOR_MULT_DOSStub_ebb2 {
  strings:
    $key_ebb2 = { bf da [2] cb c2 [2] 8c c0 [2] cb d1 [2] 85 dd [2] 89 d7 [2] 9e dc [2] 85 92 [2] b8 }

  condition:
    any of them
}