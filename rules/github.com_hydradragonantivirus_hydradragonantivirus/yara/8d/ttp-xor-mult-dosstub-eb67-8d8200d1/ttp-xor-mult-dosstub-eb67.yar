rule TTP_XOR_MULT_DOSStub_eb67 {
  strings:
    $key_eb67 = { bf 0f [2] cb 17 [2] 8c 15 [2] cb 04 [2] 85 08 [2] 89 02 [2] 9e 09 [2] 85 47 [2] b8 }

  condition:
    any of them
}