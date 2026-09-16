rule TTP_XOR_MULT_DOSStub_eb7e {
  strings:
    $key_eb7e = { bf 16 [2] cb 0e [2] 8c 0c [2] cb 1d [2] 85 11 [2] 89 1b [2] 9e 10 [2] 85 5e [2] b8 }

  condition:
    any of them
}