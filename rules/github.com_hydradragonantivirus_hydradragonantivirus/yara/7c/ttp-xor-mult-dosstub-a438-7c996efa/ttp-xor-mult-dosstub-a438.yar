rule TTP_XOR_MULT_DOSStub_a438 {
  strings:
    $key_a438 = { f0 50 [2] 84 48 [2] c3 4a [2] 84 5b [2] ca 57 [2] c6 5d [2] d1 56 [2] ca 18 [2] f7 }

  condition:
    any of them
}