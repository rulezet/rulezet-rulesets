rule TTP_XOR_MULT_DOSStub_eb75 {
  strings:
    $key_eb75 = { bf 1d [2] cb 05 [2] 8c 07 [2] cb 16 [2] 85 1a [2] 89 10 [2] 9e 1b [2] 85 55 [2] b8 }

  condition:
    any of them
}