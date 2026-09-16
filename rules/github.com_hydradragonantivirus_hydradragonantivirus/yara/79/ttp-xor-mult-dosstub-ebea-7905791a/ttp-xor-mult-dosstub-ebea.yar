rule TTP_XOR_MULT_DOSStub_ebea {
  strings:
    $key_ebea = { bf 82 [2] cb 9a [2] 8c 98 [2] cb 89 [2] 85 85 [2] 89 8f [2] 9e 84 [2] 85 ca [2] b8 }

  condition:
    any of them
}