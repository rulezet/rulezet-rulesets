rule TTP_XOR_MULT_DOSStub_eb62 {
  strings:
    $key_eb62 = { bf 0a [2] cb 12 [2] 8c 10 [2] cb 01 [2] 85 0d [2] 89 07 [2] 9e 0c [2] 85 42 [2] b8 }

  condition:
    any of them
}