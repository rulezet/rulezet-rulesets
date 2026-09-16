rule TTP_XOR_MULT_DOSStub_a057 {
  strings:
    $key_a057 = { f4 3f [2] 80 27 [2] c7 25 [2] 80 34 [2] ce 38 [2] c2 32 [2] d5 39 [2] ce 77 [2] f3 }

  condition:
    any of them
}