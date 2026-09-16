rule TTP_XOR_MULT_DOSStub_a1e7 {
  strings:
    $key_a1e7 = { f5 8f [2] 81 97 [2] c6 95 [2] 81 84 [2] cf 88 [2] c3 82 [2] d4 89 [2] cf c7 [2] f2 }

  condition:
    any of them
}