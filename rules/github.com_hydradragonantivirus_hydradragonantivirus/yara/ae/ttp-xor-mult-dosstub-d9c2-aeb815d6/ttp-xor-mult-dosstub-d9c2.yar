rule TTP_XOR_MULT_DOSStub_d9c2 {
  strings:
    $key_d9c2 = { 8d aa [2] f9 b2 [2] be b0 [2] f9 a1 [2] b7 ad [2] bb a7 [2] ac ac [2] b7 e2 [2] 8a }

  condition:
    any of them
}