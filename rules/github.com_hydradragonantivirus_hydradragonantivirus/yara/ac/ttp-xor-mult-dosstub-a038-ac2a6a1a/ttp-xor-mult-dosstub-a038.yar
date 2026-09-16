rule TTP_XOR_MULT_DOSStub_a038 {
  strings:
    $key_a038 = { f4 50 [2] 80 48 [2] c7 4a [2] 80 5b [2] ce 57 [2] c2 5d [2] d5 56 [2] ce 18 [2] f3 }

  condition:
    any of them
}