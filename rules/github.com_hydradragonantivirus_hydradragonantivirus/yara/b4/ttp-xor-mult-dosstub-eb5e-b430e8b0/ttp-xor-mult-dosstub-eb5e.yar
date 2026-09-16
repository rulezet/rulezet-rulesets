rule TTP_XOR_MULT_DOSStub_eb5e {
  strings:
    $key_eb5e = { bf 36 [2] cb 2e [2] 8c 2c [2] cb 3d [2] 85 31 [2] 89 3b [2] 9e 30 [2] 85 7e [2] b8 }

  condition:
    any of them
}