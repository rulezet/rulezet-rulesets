rule TTP_XOR_MULT_DOSStub_ebef {
  strings:
    $key_ebef = { bf 87 [2] cb 9f [2] 8c 9d [2] cb 8c [2] 85 80 [2] 89 8a [2] 9e 81 [2] 85 cf [2] b8 }

  condition:
    any of them
}