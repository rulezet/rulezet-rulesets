rule TTP_XOR_MULT_DOSStub_eb7a {
  strings:
    $key_eb7a = { bf 12 [2] cb 0a [2] 8c 08 [2] cb 19 [2] 85 15 [2] 89 1f [2] 9e 14 [2] 85 5a [2] b8 }

  condition:
    any of them
}