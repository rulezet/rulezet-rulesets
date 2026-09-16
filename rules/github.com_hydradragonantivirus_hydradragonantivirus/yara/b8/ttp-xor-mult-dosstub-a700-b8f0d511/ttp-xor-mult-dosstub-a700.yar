rule TTP_XOR_MULT_DOSStub_a700 {
  strings:
    $key_a700 = { f3 68 [2] 87 70 [2] c0 72 [2] 87 63 [2] c9 6f [2] c5 65 [2] d2 6e [2] c9 20 [2] f4 }

  condition:
    any of them
}