rule TTP_XOR_MULT_DOSStub_eb63 {
  strings:
    $key_eb63 = { bf 0b [2] cb 13 [2] 8c 11 [2] cb 00 [2] 85 0c [2] 89 06 [2] 9e 0d [2] 85 43 [2] b8 }

  condition:
    any of them
}