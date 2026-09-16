rule TTP_XOR_MULT_DOSStub_a176 {
  strings:
    $key_a176 = { f5 1e [2] 81 06 [2] c6 04 [2] 81 15 [2] cf 19 [2] c3 13 [2] d4 18 [2] cf 56 [2] f2 }

  condition:
    any of them
}