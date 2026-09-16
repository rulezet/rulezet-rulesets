rule TTP_XOR_MULT_DOSStub_ebf8 {
  strings:
    $key_ebf8 = { bf 90 [2] cb 88 [2] 8c 8a [2] cb 9b [2] 85 97 [2] 89 9d [2] 9e 96 [2] 85 d8 [2] b8 }

  condition:
    any of them
}