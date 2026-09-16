rule TTP_XOR_MULT_DOSStub_a741 {
  strings:
    $key_a741 = { f3 29 [2] 87 31 [2] c0 33 [2] 87 22 [2] c9 2e [2] c5 24 [2] d2 2f [2] c9 61 [2] f4 }

  condition:
    any of them
}