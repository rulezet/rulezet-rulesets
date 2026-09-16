rule TTP_XOR_MULT_DOSStub_d9c9 {
  strings:
    $key_d9c9 = { 8d a1 [2] f9 b9 [2] be bb [2] f9 aa [2] b7 a6 [2] bb ac [2] ac a7 [2] b7 e9 [2] 8a }

  condition:
    any of them
}