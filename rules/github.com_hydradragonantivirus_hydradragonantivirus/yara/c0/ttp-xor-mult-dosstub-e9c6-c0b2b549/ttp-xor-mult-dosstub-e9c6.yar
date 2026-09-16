rule TTP_XOR_MULT_DOSStub_e9c6 {
  strings:
    $key_e9c6 = { bd ae [2] c9 b6 [2] 8e b4 [2] c9 a5 [2] 87 a9 [2] 8b a3 [2] 9c a8 [2] 87 e6 [2] ba }

  condition:
    any of them
}