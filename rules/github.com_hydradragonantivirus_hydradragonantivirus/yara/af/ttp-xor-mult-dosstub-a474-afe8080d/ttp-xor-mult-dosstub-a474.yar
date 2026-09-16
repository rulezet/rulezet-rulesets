rule TTP_XOR_MULT_DOSStub_a474 {
  strings:
    $key_a474 = { f0 1c [2] 84 04 [2] c3 06 [2] 84 17 [2] ca 1b [2] c6 11 [2] d1 1a [2] ca 54 [2] f7 }

  condition:
    any of them
}