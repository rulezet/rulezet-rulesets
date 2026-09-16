rule TTP_XOR_MULT_DOSStub_e9c1 {
  strings:
    $key_e9c1 = { bd a9 [2] c9 b1 [2] 8e b3 [2] c9 a2 [2] 87 ae [2] 8b a4 [2] 9c af [2] 87 e1 [2] ba }

  condition:
    any of them
}