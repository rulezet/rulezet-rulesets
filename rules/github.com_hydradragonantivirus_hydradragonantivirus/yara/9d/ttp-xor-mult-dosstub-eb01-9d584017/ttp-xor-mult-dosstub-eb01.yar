rule TTP_XOR_MULT_DOSStub_eb01 {
  strings:
    $key_eb01 = { bf 69 [2] cb 71 [2] 8c 73 [2] cb 62 [2] 85 6e [2] 89 64 [2] 9e 6f [2] 85 21 [2] b8 }

  condition:
    any of them
}