rule TTP_XOR_MULT_DOSStub_eb12 {
  strings:
    $key_eb12 = { bf 7a [2] cb 62 [2] 8c 60 [2] cb 71 [2] 85 7d [2] 89 77 [2] 9e 7c [2] 85 32 [2] b8 }

  condition:
    any of them
}