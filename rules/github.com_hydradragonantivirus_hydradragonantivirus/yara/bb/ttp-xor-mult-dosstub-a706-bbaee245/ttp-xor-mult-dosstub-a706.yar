rule TTP_XOR_MULT_DOSStub_a706 {
  strings:
    $key_a706 = { f3 6e [2] 87 76 [2] c0 74 [2] 87 65 [2] c9 69 [2] c5 63 [2] d2 68 [2] c9 26 [2] f4 }

  condition:
    any of them
}