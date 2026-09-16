rule TTP_XOR_MULT_DOSStub_eb55 {
  strings:
    $key_eb55 = { bf 3d [2] cb 25 [2] 8c 27 [2] cb 36 [2] 85 3a [2] 89 30 [2] 9e 3b [2] 85 75 [2] b8 }

  condition:
    any of them
}