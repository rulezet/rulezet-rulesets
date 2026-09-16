rule TTP_XOR_MULT_DOSStub_a463 {
  strings:
    $key_a463 = { f0 0b [2] 84 13 [2] c3 11 [2] 84 00 [2] ca 0c [2] c6 06 [2] d1 0d [2] ca 43 [2] f7 }

  condition:
    any of them
}