rule TTP_XOR_MULT_DOSStub_a475 {
  strings:
    $key_a475 = { f0 1d [2] 84 05 [2] c3 07 [2] 84 16 [2] ca 1a [2] c6 10 [2] d1 1b [2] ca 55 [2] f7 }

  condition:
    any of them
}