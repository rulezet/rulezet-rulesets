rule TTP_XOR_MULT_DOSStub_a039 {
  strings:
    $key_a039 = { f4 51 [2] 80 49 [2] c7 4b [2] 80 5a [2] ce 56 [2] c2 5c [2] d5 57 [2] ce 19 [2] f3 }

  condition:
    any of them
}