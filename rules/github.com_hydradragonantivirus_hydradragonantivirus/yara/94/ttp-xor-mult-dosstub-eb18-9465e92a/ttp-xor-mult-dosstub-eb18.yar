rule TTP_XOR_MULT_DOSStub_eb18 {
  strings:
    $key_eb18 = { bf 70 [2] cb 68 [2] 8c 6a [2] cb 7b [2] 85 77 [2] 89 7d [2] 9e 76 [2] 85 38 [2] b8 }

  condition:
    any of them
}