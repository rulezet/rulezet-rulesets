rule TTP_XOR_MULT_DOSStub_eb00 {
  strings:
    $key_eb00 = { bf 68 [2] cb 70 [2] 8c 72 [2] cb 63 [2] 85 6f [2] 89 65 [2] 9e 6e [2] 85 20 [2] b8 }

  condition:
    any of them
}