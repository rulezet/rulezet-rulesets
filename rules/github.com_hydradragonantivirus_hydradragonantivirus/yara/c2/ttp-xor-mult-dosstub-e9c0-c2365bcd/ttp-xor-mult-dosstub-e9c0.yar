rule TTP_XOR_MULT_DOSStub_e9c0 {
  strings:
    $key_e9c0 = { bd a8 [2] c9 b0 [2] 8e b2 [2] c9 a3 [2] 87 af [2] 8b a5 [2] 9c ae [2] 87 e0 [2] ba }

  condition:
    any of them
}