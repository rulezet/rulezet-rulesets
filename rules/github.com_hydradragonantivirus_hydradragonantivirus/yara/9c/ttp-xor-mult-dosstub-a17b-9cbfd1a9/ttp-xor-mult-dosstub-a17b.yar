rule TTP_XOR_MULT_DOSStub_a17b {
  strings:
    $key_a17b = { f5 13 [2] 81 0b [2] c6 09 [2] 81 18 [2] cf 14 [2] c3 1e [2] d4 15 [2] cf 5b [2] f2 }

  condition:
    any of them
}