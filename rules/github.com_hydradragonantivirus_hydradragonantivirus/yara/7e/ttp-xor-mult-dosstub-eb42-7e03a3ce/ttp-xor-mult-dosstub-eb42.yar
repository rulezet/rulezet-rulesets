rule TTP_XOR_MULT_DOSStub_eb42 {
  strings:
    $key_eb42 = { bf 2a [2] cb 32 [2] 8c 30 [2] cb 21 [2] 85 2d [2] 89 27 [2] 9e 2c [2] 85 62 [2] b8 }

  condition:
    any of them
}