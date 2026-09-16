rule TTP_XOR_MULT_DOSStub_a032 {
  strings:
    $key_a032 = { f4 5a [2] 80 42 [2] c7 40 [2] 80 51 [2] ce 5d [2] c2 57 [2] d5 5c [2] ce 12 [2] f3 }

  condition:
    any of them
}