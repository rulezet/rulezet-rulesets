rule TTP_XOR_MULT_DOSStub_a70b {
  strings:
    $key_a70b = { f3 63 [2] 87 7b [2] c0 79 [2] 87 68 [2] c9 64 [2] c5 6e [2] d2 65 [2] c9 2b [2] f4 }

  condition:
    any of them
}