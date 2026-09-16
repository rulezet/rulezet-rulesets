rule TTP_XOR_MULT_DOSStub_eb31 {
  strings:
    $key_eb31 = { bf 59 [2] cb 41 [2] 8c 43 [2] cb 52 [2] 85 5e [2] 89 54 [2] 9e 5f [2] 85 11 [2] b8 }

  condition:
    any of them
}