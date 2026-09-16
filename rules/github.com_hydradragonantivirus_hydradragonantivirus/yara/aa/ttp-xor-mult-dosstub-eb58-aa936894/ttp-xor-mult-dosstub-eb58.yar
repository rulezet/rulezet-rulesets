rule TTP_XOR_MULT_DOSStub_eb58 {
  strings:
    $key_eb58 = { bf 30 [2] cb 28 [2] 8c 2a [2] cb 3b [2] 85 37 [2] 89 3d [2] 9e 36 [2] 85 78 [2] b8 }

  condition:
    any of them
}