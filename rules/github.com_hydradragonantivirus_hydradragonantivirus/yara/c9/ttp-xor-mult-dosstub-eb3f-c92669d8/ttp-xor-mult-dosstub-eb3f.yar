rule TTP_XOR_MULT_DOSStub_eb3f {
  strings:
    $key_eb3f = { bf 57 [2] cb 4f [2] 8c 4d [2] cb 5c [2] 85 50 [2] 89 5a [2] 9e 51 [2] 85 1f [2] b8 }

  condition:
    any of them
}