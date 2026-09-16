rule TTP_XOR_MULT_DOSStub_eb27 {
  strings:
    $key_eb27 = { bf 4f [2] cb 57 [2] 8c 55 [2] cb 44 [2] 85 48 [2] 89 42 [2] 9e 49 [2] 85 07 [2] b8 }

  condition:
    any of them
}