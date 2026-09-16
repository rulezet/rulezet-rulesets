rule TTP_XOR_MULT_DOSStub_a479 {
  strings:
    $key_a479 = { f0 11 [2] 84 09 [2] c3 0b [2] 84 1a [2] ca 16 [2] c6 1c [2] d1 17 [2] ca 59 [2] f7 }

  condition:
    any of them
}