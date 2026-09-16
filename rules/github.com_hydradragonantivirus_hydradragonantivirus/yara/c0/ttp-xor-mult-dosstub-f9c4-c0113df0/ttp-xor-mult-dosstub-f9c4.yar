rule TTP_XOR_MULT_DOSStub_f9c4 {
  strings:
    $key_f9c4 = { ad ac [2] d9 b4 [2] 9e b6 [2] d9 a7 [2] 97 ab [2] 9b a1 [2] 8c aa [2] 97 e4 [2] aa }

  condition:
    any of them
}