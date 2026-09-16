rule TTP_XOR_MULT_DOSStub_e9b9 {
  strings:
    $key_e9b9 = { bd d1 [2] c9 c9 [2] 8e cb [2] c9 da [2] 87 d6 [2] 8b dc [2] 9c d7 [2] 87 99 [2] ba }

  condition:
    any of them
}