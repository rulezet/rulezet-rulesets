rule TTP_XOR_MULT_DOSStub_ebb3 {
  strings:
    $key_ebb3 = { bf db [2] cb c3 [2] 8c c1 [2] cb d0 [2] 85 dc [2] 89 d6 [2] 9e dd [2] 85 93 [2] b8 }

  condition:
    any of them
}