rule TTP_XOR_MULT_DOSStub_ebe8 {
  strings:
    $key_ebe8 = { bf 80 [2] cb 98 [2] 8c 9a [2] cb 8b [2] 85 87 [2] 89 8d [2] 9e 86 [2] 85 c8 [2] b8 }

  condition:
    any of them
}