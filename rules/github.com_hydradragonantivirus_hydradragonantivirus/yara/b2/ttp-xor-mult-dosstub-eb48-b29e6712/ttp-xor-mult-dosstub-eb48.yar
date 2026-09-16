rule TTP_XOR_MULT_DOSStub_eb48 {
  strings:
    $key_eb48 = { bf 20 [2] cb 38 [2] 8c 3a [2] cb 2b [2] 85 27 [2] 89 2d [2] 9e 26 [2] 85 68 [2] b8 }

  condition:
    any of them
}