rule TTP_XOR_MULT_DOSStub_eb19 {
  strings:
    $key_eb19 = { bf 71 [2] cb 69 [2] 8c 6b [2] cb 7a [2] 85 76 [2] 89 7c [2] 9e 77 [2] 85 39 [2] b8 }

  condition:
    any of them
}