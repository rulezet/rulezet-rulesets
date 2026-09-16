rule TTP_XOR_MULT_DOSStub_a1f0 {
  strings:
    $key_a1f0 = { f5 98 [2] 81 80 [2] c6 82 [2] 81 93 [2] cf 9f [2] c3 95 [2] d4 9e [2] cf d0 [2] f2 }

  condition:
    any of them
}