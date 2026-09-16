rule TTP_XOR_MULT_DOSStub_eb68 {
  strings:
    $key_eb68 = { bf 00 [2] cb 18 [2] 8c 1a [2] cb 0b [2] 85 07 [2] 89 0d [2] 9e 06 [2] 85 48 [2] b8 }

  condition:
    any of them
}