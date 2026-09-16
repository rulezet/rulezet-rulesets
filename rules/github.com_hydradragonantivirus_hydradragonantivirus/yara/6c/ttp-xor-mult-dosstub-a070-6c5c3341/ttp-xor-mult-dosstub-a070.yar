rule TTP_XOR_MULT_DOSStub_a070 {
  strings:
    $key_a070 = { f4 18 [2] 80 00 [2] c7 02 [2] 80 13 [2] ce 1f [2] c2 15 [2] d5 1e [2] ce 50 [2] f3 }

  condition:
    any of them
}