rule TTP_XOR_MULT_DOSStub_a773 {
  strings:
    $key_a773 = { f3 1b [2] 87 03 [2] c0 01 [2] 87 10 [2] c9 1c [2] c5 16 [2] d2 1d [2] c9 53 [2] f4 }

  condition:
    any of them
}