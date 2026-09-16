rule TTP_XOR_MULT_DOSStub_b385 {
  strings:
    $key_b385 = { e7 ed [2] 93 f5 [2] d4 f7 [2] 93 e6 [2] dd ea [2] d1 e0 [2] c6 eb [2] dd a5 [2] e0 }

  condition:
    any of them
}