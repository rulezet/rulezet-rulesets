rule TTP_XOR_MULT_DOSStub_b4cb {
  strings:
    $key_b4cb = { e0 a3 [2] 94 bb [2] d3 b9 [2] 94 a8 [2] da a4 [2] d6 ae [2] c1 a5 [2] da eb [2] e7 }

  condition:
    any of them
}