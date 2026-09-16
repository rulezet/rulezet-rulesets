rule TTP_XOR_MULT_DOSStub_a754 {
  strings:
    $key_a754 = { f3 3c [2] 87 24 [2] c0 26 [2] 87 37 [2] c9 3b [2] c5 31 [2] d2 3a [2] c9 74 [2] f4 }

  condition:
    any of them
}