rule TTP_XOR_MULT_DOSStub_a1f7 {
  strings:
    $key_a1f7 = { f5 9f [2] 81 87 [2] c6 85 [2] 81 94 [2] cf 98 [2] c3 92 [2] d4 99 [2] cf d7 [2] f2 }

  condition:
    any of them
}