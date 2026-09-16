rule TTP_XOR_MULT_DOSStub_eb0a {
  strings:
    $key_eb0a = { bf 62 [2] cb 7a [2] 8c 78 [2] cb 69 [2] 85 65 [2] 89 6f [2] 9e 64 [2] 85 2a [2] b8 }

  condition:
    any of them
}