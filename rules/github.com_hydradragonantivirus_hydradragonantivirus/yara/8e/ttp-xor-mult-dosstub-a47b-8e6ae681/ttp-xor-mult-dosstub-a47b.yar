rule TTP_XOR_MULT_DOSStub_a47b {
  strings:
    $key_a47b = { f0 13 [2] 84 0b [2] c3 09 [2] 84 18 [2] ca 14 [2] c6 1e [2] d1 15 [2] ca 5b [2] f7 }

  condition:
    any of them
}