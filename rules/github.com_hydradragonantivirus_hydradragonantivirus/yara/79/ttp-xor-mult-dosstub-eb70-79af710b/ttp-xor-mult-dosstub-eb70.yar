rule TTP_XOR_MULT_DOSStub_eb70 {
  strings:
    $key_eb70 = { bf 18 [2] cb 00 [2] 8c 02 [2] cb 13 [2] 85 1f [2] 89 15 [2] 9e 1e [2] 85 50 [2] b8 }

  condition:
    any of them
}