rule TTP_XOR_MULT_DOSStub_eb4a {
  strings:
    $key_eb4a = { bf 22 [2] cb 3a [2] 8c 38 [2] cb 29 [2] 85 25 [2] 89 2f [2] 9e 24 [2] 85 6a [2] b8 }

  condition:
    any of them
}