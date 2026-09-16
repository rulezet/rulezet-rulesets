rule TTP_XOR_MULT_DOSStub_a708 {
  strings:
    $key_a708 = { f3 60 [2] 87 78 [2] c0 7a [2] 87 6b [2] c9 67 [2] c5 6d [2] d2 66 [2] c9 28 [2] f4 }

  condition:
    any of them
}