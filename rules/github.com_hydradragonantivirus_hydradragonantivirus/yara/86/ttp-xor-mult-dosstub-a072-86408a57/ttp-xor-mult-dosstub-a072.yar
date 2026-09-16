rule TTP_XOR_MULT_DOSStub_a072 {
  strings:
    $key_a072 = { f4 1a [2] 80 02 [2] c7 00 [2] 80 11 [2] ce 1d [2] c2 17 [2] d5 1c [2] ce 52 [2] f3 }

  condition:
    any of them
}