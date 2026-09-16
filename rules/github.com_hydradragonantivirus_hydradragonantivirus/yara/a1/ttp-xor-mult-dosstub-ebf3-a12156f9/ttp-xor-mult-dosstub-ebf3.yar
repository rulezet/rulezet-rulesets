rule TTP_XOR_MULT_DOSStub_ebf3 {
  strings:
    $key_ebf3 = { bf 9b [2] cb 83 [2] 8c 81 [2] cb 90 [2] 85 9c [2] 89 96 [2] 9e 9d [2] 85 d3 [2] b8 }

  condition:
    any of them
}