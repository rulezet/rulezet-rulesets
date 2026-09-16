rule TTP_XOR_MULT_DOSStub_a4f7 {
  strings:
    $key_a4f7 = { f0 9f [2] 84 87 [2] c3 85 [2] 84 94 [2] ca 98 [2] c6 92 [2] d1 99 [2] ca d7 [2] f7 }

  condition:
    any of them
}