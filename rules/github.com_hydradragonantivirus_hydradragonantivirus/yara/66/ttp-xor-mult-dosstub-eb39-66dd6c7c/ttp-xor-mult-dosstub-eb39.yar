rule TTP_XOR_MULT_DOSStub_eb39 {
  strings:
    $key_eb39 = { bf 51 [2] cb 49 [2] 8c 4b [2] cb 5a [2] 85 56 [2] 89 5c [2] 9e 57 [2] 85 19 [2] b8 }

  condition:
    any of them
}