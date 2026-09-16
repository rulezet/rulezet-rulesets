rule TTP_XOR_MULT_DOSStub_e9b1 {
  strings:
    $key_e9b1 = { bd d9 [2] c9 c1 [2] 8e c3 [2] c9 d2 [2] 87 de [2] 8b d4 [2] 9c df [2] 87 91 [2] ba }

  condition:
    any of them
}