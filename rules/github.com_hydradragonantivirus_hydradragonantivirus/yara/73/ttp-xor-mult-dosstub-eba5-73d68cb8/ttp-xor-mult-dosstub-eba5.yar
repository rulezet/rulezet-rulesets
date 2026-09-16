rule TTP_XOR_MULT_DOSStub_eba5 {
  strings:
    $key_eba5 = { bf cd [2] cb d5 [2] 8c d7 [2] cb c6 [2] 85 ca [2] 89 c0 [2] 9e cb [2] 85 85 [2] b8 }

  condition:
    any of them
}