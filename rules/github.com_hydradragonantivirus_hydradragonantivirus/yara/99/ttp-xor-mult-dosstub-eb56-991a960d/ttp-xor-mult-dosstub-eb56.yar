rule TTP_XOR_MULT_DOSStub_eb56 {
  strings:
    $key_eb56 = { bf 3e [2] cb 26 [2] 8c 24 [2] cb 35 [2] 85 39 [2] 89 33 [2] 9e 38 [2] 85 76 [2] b8 }

  condition:
    any of them
}