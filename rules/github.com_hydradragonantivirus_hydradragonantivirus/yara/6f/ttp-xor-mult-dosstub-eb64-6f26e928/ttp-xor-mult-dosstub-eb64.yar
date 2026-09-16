rule TTP_XOR_MULT_DOSStub_eb64 {
  strings:
    $key_eb64 = { bf 0c [2] cb 14 [2] 8c 16 [2] cb 07 [2] 85 0b [2] 89 01 [2] 9e 0a [2] 85 44 [2] b8 }

  condition:
    any of them
}