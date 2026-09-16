rule TTP_XOR_MULT_DOSStub_a468 {
  strings:
    $key_a468 = { f0 00 [2] 84 18 [2] c3 1a [2] 84 0b [2] ca 07 [2] c6 0d [2] d1 06 [2] ca 48 [2] f7 }

  condition:
    any of them
}