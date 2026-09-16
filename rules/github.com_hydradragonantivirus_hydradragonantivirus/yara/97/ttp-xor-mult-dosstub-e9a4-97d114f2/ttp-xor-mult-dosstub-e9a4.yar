rule TTP_XOR_MULT_DOSStub_e9a4 {
  strings:
    $key_e9a4 = { bd cc [2] c9 d4 [2] 8e d6 [2] c9 c7 [2] 87 cb [2] 8b c1 [2] 9c ca [2] 87 84 [2] ba }

  condition:
    any of them
}