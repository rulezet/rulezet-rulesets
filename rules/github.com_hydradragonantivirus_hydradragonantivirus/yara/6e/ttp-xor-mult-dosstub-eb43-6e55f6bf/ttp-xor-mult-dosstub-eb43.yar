rule TTP_XOR_MULT_DOSStub_eb43 {
  strings:
    $key_eb43 = { bf 2b [2] cb 33 [2] 8c 31 [2] cb 20 [2] 85 2c [2] 89 26 [2] 9e 2d [2] 85 63 [2] b8 }

  condition:
    any of them
}