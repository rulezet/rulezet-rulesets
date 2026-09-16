rule TTP_XOR_MULT_DOSStub_eb24 {
  strings:
    $key_eb24 = { bf 4c [2] cb 54 [2] 8c 56 [2] cb 47 [2] 85 4b [2] 89 41 [2] 9e 4a [2] 85 04 [2] b8 }

  condition:
    any of them
}