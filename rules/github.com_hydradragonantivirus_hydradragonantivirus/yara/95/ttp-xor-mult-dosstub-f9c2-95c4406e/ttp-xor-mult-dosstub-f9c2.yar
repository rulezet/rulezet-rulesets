rule TTP_XOR_MULT_DOSStub_f9c2 {
  strings:
    $key_f9c2 = { ad aa [2] d9 b2 [2] 9e b0 [2] d9 a1 [2] 97 ad [2] 9b a7 [2] 8c ac [2] 97 e2 [2] aa }

  condition:
    any of them
}