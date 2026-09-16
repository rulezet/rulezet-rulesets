rule TTP_XOR_MULT_DOSStub_a4f1 {
  strings:
    $key_a4f1 = { f0 99 [2] 84 81 [2] c3 83 [2] 84 92 [2] ca 9e [2] c6 94 [2] d1 9f [2] ca d1 [2] f7 }

  condition:
    any of them
}