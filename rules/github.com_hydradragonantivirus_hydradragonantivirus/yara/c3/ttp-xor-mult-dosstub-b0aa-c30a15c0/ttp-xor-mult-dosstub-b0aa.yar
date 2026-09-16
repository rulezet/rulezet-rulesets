rule TTP_XOR_MULT_DOSStub_b0aa {
  strings:
    $key_b0aa = { e4 c2 [2] 90 da [2] d7 d8 [2] 90 c9 [2] de c5 [2] d2 cf [2] c5 c4 [2] de 8a [2] e3 }

  condition:
    any of them
}