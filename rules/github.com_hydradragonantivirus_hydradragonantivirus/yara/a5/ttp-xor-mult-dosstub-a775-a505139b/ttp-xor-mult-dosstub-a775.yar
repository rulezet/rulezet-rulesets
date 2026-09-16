rule TTP_XOR_MULT_DOSStub_a775 {
  strings:
    $key_a775 = { f3 1d [2] 87 05 [2] c0 07 [2] 87 16 [2] c9 1a [2] c5 10 [2] d2 1b [2] c9 55 [2] f4 }

  condition:
    any of them
}