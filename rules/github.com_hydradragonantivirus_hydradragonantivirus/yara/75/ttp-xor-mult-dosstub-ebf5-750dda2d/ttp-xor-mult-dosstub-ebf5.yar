rule TTP_XOR_MULT_DOSStub_ebf5 {
  strings:
    $key_ebf5 = { bf 9d [2] cb 85 [2] 8c 87 [2] cb 96 [2] 85 9a [2] 89 90 [2] 9e 9b [2] 85 d5 [2] b8 }

  condition:
    any of them
}