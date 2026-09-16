rule TTP_XOR_MULT_DOSStub_eb2a {
  strings:
    $key_eb2a = { bf 42 [2] cb 5a [2] 8c 58 [2] cb 49 [2] 85 45 [2] 89 4f [2] 9e 44 [2] 85 0a [2] b8 }

  condition:
    any of them
}