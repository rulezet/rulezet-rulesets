rule TTP_XOR_MULT_DOSStub_eb60 {
  strings:
    $key_eb60 = { bf 08 [2] cb 10 [2] 8c 12 [2] cb 03 [2] 85 0f [2] 89 05 [2] 9e 0e [2] 85 40 [2] b8 }

  condition:
    any of them
}