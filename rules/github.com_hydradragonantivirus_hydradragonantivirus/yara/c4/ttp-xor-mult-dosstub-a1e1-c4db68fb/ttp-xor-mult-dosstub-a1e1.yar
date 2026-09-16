rule TTP_XOR_MULT_DOSStub_a1e1 {
  strings:
    $key_a1e1 = { f5 89 [2] 81 91 [2] c6 93 [2] 81 82 [2] cf 8e [2] c3 84 [2] d4 8f [2] cf c1 [2] f2 }

  condition:
    any of them
}