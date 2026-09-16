rule TTP_XOR_MULT_DOSStub_a750 {
  strings:
    $key_a750 = { f3 38 [2] 87 20 [2] c0 22 [2] 87 33 [2] c9 3f [2] c5 35 [2] d2 3e [2] c9 70 [2] f4 }

  condition:
    any of them
}