rule TTP_XOR_MULT_DOSStub_ebf7 {
  strings:
    $key_ebf7 = { bf 9f [2] cb 87 [2] 8c 85 [2] cb 94 [2] 85 98 [2] 89 92 [2] 9e 99 [2] 85 d7 [2] b8 }

  condition:
    any of them
}