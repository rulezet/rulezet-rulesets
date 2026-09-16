rule TTP_XOR_MULT_DOSStub_ebe7 {
  strings:
    $key_ebe7 = { bf 8f [2] cb 97 [2] 8c 95 [2] cb 84 [2] 85 88 [2] 89 82 [2] 9e 89 [2] 85 c7 [2] b8 }

  condition:
    any of them
}