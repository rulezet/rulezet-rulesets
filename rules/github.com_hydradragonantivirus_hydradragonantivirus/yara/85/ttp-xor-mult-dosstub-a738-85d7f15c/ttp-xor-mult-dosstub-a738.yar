rule TTP_XOR_MULT_DOSStub_a738 {
  strings:
    $key_a738 = { f3 50 [2] 87 48 [2] c0 4a [2] 87 5b [2] c9 57 [2] c5 5d [2] d2 56 [2] c9 18 [2] f4 }

  condition:
    any of them
}