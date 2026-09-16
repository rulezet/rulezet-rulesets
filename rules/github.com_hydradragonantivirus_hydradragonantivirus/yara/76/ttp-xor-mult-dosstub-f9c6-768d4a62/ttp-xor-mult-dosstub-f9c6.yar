rule TTP_XOR_MULT_DOSStub_f9c6 {
  strings:
    $key_f9c6 = { ad ae [2] d9 b6 [2] 9e b4 [2] d9 a5 [2] 97 a9 [2] 9b a3 [2] 8c a8 [2] 97 e6 [2] aa }

  condition:
    any of them
}