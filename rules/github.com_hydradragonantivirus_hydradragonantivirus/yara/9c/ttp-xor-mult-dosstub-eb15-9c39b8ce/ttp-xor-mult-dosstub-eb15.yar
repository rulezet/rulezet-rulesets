rule TTP_XOR_MULT_DOSStub_eb15 {
  strings:
    $key_eb15 = { bf 7d [2] cb 65 [2] 8c 67 [2] cb 76 [2] 85 7a [2] 89 70 [2] 9e 7b [2] 85 35 [2] b8 }

  condition:
    any of them
}