rule TTP_XOR_MULT_DOSStub_f9c7 {
  strings:
    $key_f9c7 = { ad af [2] d9 b7 [2] 9e b5 [2] d9 a4 [2] 97 a8 [2] 9b a2 [2] 8c a9 [2] 97 e7 [2] aa }

  condition:
    any of them
}