rule TTP_XOR_MULT_DOSStub_a779 {
  strings:
    $key_a779 = { f3 11 [2] 87 09 [2] c0 0b [2] 87 1a [2] c9 16 [2] c5 1c [2] d2 17 [2] c9 59 [2] f4 }

  condition:
    any of them
}