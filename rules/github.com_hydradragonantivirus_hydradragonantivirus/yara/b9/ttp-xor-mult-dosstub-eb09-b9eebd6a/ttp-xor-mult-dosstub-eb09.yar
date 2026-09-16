rule TTP_XOR_MULT_DOSStub_eb09 {
  strings:
    $key_eb09 = { bf 61 [2] cb 79 [2] 8c 7b [2] cb 6a [2] 85 66 [2] 89 6c [2] 9e 67 [2] 85 29 [2] b8 }

  condition:
    any of them
}