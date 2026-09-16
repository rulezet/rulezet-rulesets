rule TTP_XOR_MULT_DOSStub_eb30 {
  strings:
    $key_eb30 = { bf 58 [2] cb 40 [2] 8c 42 [2] cb 53 [2] 85 5f [2] 89 55 [2] 9e 5e [2] 85 10 [2] b8 }

  condition:
    any of them
}