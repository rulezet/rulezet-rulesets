rule TTP_XOR_MULT_DOSStub_eb41 {
  strings:
    $key_eb41 = { bf 29 [2] cb 31 [2] 8c 33 [2] cb 22 [2] 85 2e [2] 89 24 [2] 9e 2f [2] 85 61 [2] b8 }

  condition:
    any of them
}