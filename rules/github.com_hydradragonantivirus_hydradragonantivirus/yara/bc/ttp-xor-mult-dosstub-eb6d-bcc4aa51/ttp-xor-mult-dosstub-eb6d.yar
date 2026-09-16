rule TTP_XOR_MULT_DOSStub_eb6d {
  strings:
    $key_eb6d = { bf 05 [2] cb 1d [2] 8c 1f [2] cb 0e [2] 85 02 [2] 89 08 [2] 9e 03 [2] 85 4d [2] b8 }

  condition:
    any of them
}