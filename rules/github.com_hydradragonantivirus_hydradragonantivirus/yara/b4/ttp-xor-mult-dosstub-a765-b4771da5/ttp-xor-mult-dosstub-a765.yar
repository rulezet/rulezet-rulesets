rule TTP_XOR_MULT_DOSStub_a765 {
  strings:
    $key_a765 = { f3 0d [2] 87 15 [2] c0 17 [2] 87 06 [2] c9 0a [2] c5 00 [2] d2 0b [2] c9 45 [2] f4 }

  condition:
    any of them
}