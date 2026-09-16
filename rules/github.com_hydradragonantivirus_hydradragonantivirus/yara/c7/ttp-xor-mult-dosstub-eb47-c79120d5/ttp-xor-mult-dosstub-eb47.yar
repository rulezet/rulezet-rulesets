rule TTP_XOR_MULT_DOSStub_eb47 {
  strings:
    $key_eb47 = { bf 2f [2] cb 37 [2] 8c 35 [2] cb 24 [2] 85 28 [2] 89 22 [2] 9e 29 [2] 85 67 [2] b8 }

  condition:
    any of them
}