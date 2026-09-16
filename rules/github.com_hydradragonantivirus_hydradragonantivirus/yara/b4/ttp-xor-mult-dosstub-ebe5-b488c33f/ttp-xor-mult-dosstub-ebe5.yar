rule TTP_XOR_MULT_DOSStub_ebe5 {
  strings:
    $key_ebe5 = { bf 8d [2] cb 95 [2] 8c 97 [2] cb 86 [2] 85 8a [2] 89 80 [2] 9e 8b [2] 85 c5 [2] b8 }

  condition:
    any of them
}