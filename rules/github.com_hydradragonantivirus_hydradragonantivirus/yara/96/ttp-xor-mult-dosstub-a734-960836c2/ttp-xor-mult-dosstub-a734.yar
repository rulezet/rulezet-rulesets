rule TTP_XOR_MULT_DOSStub_a734 {
  strings:
    $key_a734 = { f3 5c [2] 87 44 [2] c0 46 [2] 87 57 [2] c9 5b [2] c5 51 [2] d2 5a [2] c9 14 [2] f4 }

  condition:
    any of them
}