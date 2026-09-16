rule TTP_XOR_MULT_DOSStub_eb34 {
  strings:
    $key_eb34 = { bf 5c [2] cb 44 [2] 8c 46 [2] cb 57 [2] 85 5b [2] 89 51 [2] 9e 5a [2] 85 14 [2] b8 }

  condition:
    any of them
}