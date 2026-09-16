rule TTP_XOR_MULT_DOSStub_a433 {
  strings:
    $key_a433 = { f0 5b [2] 84 43 [2] c3 41 [2] 84 50 [2] ca 5c [2] c6 56 [2] d1 5d [2] ca 13 [2] f7 }

  condition:
    any of them
}