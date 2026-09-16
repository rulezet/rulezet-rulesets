rule TTP_XOR_MULT_DOSStub_a764 {
  strings:
    $key_a764 = { f3 0c [2] 87 14 [2] c0 16 [2] 87 07 [2] c9 0b [2] c5 01 [2] d2 0a [2] c9 44 [2] f4 }

  condition:
    any of them
}