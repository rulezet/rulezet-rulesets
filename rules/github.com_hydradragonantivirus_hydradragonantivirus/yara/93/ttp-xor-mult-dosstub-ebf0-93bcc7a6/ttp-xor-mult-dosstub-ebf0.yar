rule TTP_XOR_MULT_DOSStub_ebf0 {
  strings:
    $key_ebf0 = { bf 98 [2] cb 80 [2] 8c 82 [2] cb 93 [2] 85 9f [2] 89 95 [2] 9e 9e [2] 85 d0 [2] b8 }

  condition:
    any of them
}