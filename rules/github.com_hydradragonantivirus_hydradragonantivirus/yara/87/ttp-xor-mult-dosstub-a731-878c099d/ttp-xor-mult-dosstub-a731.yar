rule TTP_XOR_MULT_DOSStub_a731 {
  strings:
    $key_a731 = { f3 59 [2] 87 41 [2] c0 43 [2] 87 52 [2] c9 5e [2] c5 54 [2] d2 5f [2] c9 11 [2] f4 }

  condition:
    any of them
}