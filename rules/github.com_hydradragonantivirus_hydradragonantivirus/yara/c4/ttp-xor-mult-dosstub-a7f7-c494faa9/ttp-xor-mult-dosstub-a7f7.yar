rule TTP_XOR_MULT_DOSStub_a7f7 {
  strings:
    $key_a7f7 = { f3 9f [2] 87 87 [2] c0 85 [2] 87 94 [2] c9 98 [2] c5 92 [2] d2 99 [2] c9 d7 [2] f4 }

  condition:
    any of them
}