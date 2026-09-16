rule TTP_XOR_MULT_DOSStub_eb40 {
  strings:
    $key_eb40 = { bf 28 [2] cb 30 [2] 8c 32 [2] cb 23 [2] 85 2f [2] 89 25 [2] 9e 2e [2] 85 60 [2] b8 }

  condition:
    any of them
}