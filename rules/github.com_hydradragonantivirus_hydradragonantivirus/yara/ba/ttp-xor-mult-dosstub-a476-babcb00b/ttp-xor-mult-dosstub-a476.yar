rule TTP_XOR_MULT_DOSStub_a476 {
  strings:
    $key_a476 = { f0 1e [2] 84 06 [2] c3 04 [2] 84 15 [2] ca 19 [2] c6 13 [2] d1 18 [2] ca 56 [2] f7 }

  condition:
    any of them
}