rule TTP_XOR_MULT_DOSStub_b386 {
  strings:
    $key_b386 = { e7 ee [2] 93 f6 [2] d4 f4 [2] 93 e5 [2] dd e9 [2] d1 e3 [2] c6 e8 [2] dd a6 [2] e0 }

  condition:
    any of them
}