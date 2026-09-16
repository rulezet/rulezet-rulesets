rule TTP_XOR_MULT_DOSStub_09c2 {
  strings:
    $key_09c2 = { 5d aa [2] 29 b2 [2] 6e b0 [2] 29 a1 [2] 67 ad [2] 6b a7 [2] 7c ac [2] 67 e2 [2] 5a }

  condition:
    any of them
}