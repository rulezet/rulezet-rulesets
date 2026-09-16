rule TTP_XOR_MULT_DOSStub_eb0d {
  strings:
    $key_eb0d = { bf 65 [2] cb 7d [2] 8c 7f [2] cb 6e [2] 85 62 [2] 89 68 [2] 9e 63 [2] 85 2d [2] b8 }

  condition:
    any of them
}