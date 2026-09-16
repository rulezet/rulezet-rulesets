rule TTP_XOR_MULT_DOSStub_a75b {
  strings:
    $key_a75b = { f3 33 [2] 87 2b [2] c0 29 [2] 87 38 [2] c9 34 [2] c5 3e [2] d2 35 [2] c9 7b [2] f4 }

  condition:
    any of them
}