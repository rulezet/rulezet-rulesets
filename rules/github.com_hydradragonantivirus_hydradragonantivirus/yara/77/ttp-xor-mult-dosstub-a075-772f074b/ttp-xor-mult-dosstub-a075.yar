rule TTP_XOR_MULT_DOSStub_a075 {
  strings:
    $key_a075 = { f4 1d [2] 80 05 [2] c7 07 [2] 80 16 [2] ce 1a [2] c2 10 [2] d5 1b [2] ce 55 [2] f3 }

  condition:
    any of them
}