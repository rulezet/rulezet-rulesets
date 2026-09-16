rule TTP_XOR_MULT_DOSStub_b3c0 {
  strings:
    $key_b3c0 = { e7 a8 [2] 93 b0 [2] d4 b2 [2] 93 a3 [2] dd af [2] d1 a5 [2] c6 ae [2] dd e0 [2] e0 }

  condition:
    any of them
}