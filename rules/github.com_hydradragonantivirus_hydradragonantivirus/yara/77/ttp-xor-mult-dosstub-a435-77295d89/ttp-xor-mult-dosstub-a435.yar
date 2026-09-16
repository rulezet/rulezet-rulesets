rule TTP_XOR_MULT_DOSStub_a435 {
  strings:
    $key_a435 = { f0 5d [2] 84 45 [2] c3 47 [2] 84 56 [2] ca 5a [2] c6 50 [2] d1 5b [2] ca 15 [2] f7 }

  condition:
    any of them
}