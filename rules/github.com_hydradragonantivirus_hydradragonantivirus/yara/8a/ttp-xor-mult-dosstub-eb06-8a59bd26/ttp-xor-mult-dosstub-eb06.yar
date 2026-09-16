rule TTP_XOR_MULT_DOSStub_eb06 {
  strings:
    $key_eb06 = { bf 6e [2] cb 76 [2] 8c 74 [2] cb 65 [2] 85 69 [2] 89 63 [2] 9e 68 [2] 85 26 [2] b8 }

  condition:
    any of them
}