rule TTP_XOR_MULT_DOSStub_ebe9 {
  strings:
    $key_ebe9 = { bf 81 [2] cb 99 [2] 8c 9b [2] cb 8a [2] 85 86 [2] 89 8c [2] 9e 87 [2] 85 c9 [2] b8 }

  condition:
    any of them
}