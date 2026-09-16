rule TTP_XOR_MULT_DOSStub_a705 {
  strings:
    $key_a705 = { f3 6d [2] 87 75 [2] c0 77 [2] 87 66 [2] c9 6a [2] c5 60 [2] d2 6b [2] c9 25 [2] f4 }

  condition:
    any of them
}