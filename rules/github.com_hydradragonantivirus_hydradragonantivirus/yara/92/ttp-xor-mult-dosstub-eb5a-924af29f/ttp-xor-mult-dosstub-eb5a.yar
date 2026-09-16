rule TTP_XOR_MULT_DOSStub_eb5a {
  strings:
    $key_eb5a = { bf 32 [2] cb 2a [2] 8c 28 [2] cb 39 [2] 85 35 [2] 89 3f [2] 9e 34 [2] 85 7a [2] b8 }

  condition:
    any of them
}