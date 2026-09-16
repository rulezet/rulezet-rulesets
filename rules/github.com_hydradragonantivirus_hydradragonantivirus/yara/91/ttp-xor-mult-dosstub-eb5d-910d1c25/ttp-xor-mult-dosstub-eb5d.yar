rule TTP_XOR_MULT_DOSStub_eb5d {
  strings:
    $key_eb5d = { bf 35 [2] cb 2d [2] 8c 2f [2] cb 3e [2] 85 32 [2] 89 38 [2] 9e 33 [2] 85 7d [2] b8 }

  condition:
    any of them
}