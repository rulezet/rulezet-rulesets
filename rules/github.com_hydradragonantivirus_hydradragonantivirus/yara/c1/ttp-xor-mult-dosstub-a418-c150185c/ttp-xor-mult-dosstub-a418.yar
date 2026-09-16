rule TTP_XOR_MULT_DOSStub_a418 {
  strings:
    $key_a418 = { f0 70 [2] 84 68 [2] c3 6a [2] 84 7b [2] ca 77 [2] c6 7d [2] d1 76 [2] ca 38 [2] f7 }

  condition:
    any of them
}