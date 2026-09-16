rule TTP_XOR_MULT_DOSStub_eb2e {
  strings:
    $key_eb2e = { bf 46 [2] cb 5e [2] 8c 5c [2] cb 4d [2] 85 41 [2] 89 4b [2] 9e 40 [2] 85 0e [2] b8 }

  condition:
    any of them
}