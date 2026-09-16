rule TTP_XOR_MULT_DOSStub_a777 {
  strings:
    $key_a777 = { f3 1f [2] 87 07 [2] c0 05 [2] 87 14 [2] c9 18 [2] c5 12 [2] d2 19 [2] c9 57 [2] f4 }

  condition:
    any of them
}