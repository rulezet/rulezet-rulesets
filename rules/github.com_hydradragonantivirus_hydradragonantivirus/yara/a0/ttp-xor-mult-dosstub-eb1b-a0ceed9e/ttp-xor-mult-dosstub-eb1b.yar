rule TTP_XOR_MULT_DOSStub_eb1b {
  strings:
    $key_eb1b = { bf 73 [2] cb 6b [2] 8c 69 [2] cb 78 [2] 85 74 [2] 89 7e [2] 9e 75 [2] 85 3b [2] b8 }

  condition:
    any of them
}