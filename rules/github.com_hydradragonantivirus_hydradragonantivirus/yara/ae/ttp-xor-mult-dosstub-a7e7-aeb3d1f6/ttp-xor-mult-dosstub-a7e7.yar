rule TTP_XOR_MULT_DOSStub_a7e7 {
  strings:
    $key_a7e7 = { f3 8f [2] 87 97 [2] c0 95 [2] 87 84 [2] c9 88 [2] c5 82 [2] d2 89 [2] c9 c7 [2] f4 }

  condition:
    any of them
}