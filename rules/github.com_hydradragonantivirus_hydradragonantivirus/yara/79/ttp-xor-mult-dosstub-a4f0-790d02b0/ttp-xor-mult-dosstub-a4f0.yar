rule TTP_XOR_MULT_DOSStub_a4f0 {
  strings:
    $key_a4f0 = { f0 98 [2] 84 80 [2] c3 82 [2] 84 93 [2] ca 9f [2] c6 95 [2] d1 9e [2] ca d0 [2] f7 }

  condition:
    any of them
}