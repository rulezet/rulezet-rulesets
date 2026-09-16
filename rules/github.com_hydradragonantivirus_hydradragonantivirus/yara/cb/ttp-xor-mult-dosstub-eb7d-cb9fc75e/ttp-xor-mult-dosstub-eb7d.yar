rule TTP_XOR_MULT_DOSStub_eb7d {
  strings:
    $key_eb7d = { bf 15 [2] cb 0d [2] 8c 0f [2] cb 1e [2] 85 12 [2] 89 18 [2] 9e 13 [2] 85 5d [2] b8 }

  condition:
    any of them
}