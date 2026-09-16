rule TTP_XOR_MULT_DOSStub_a7f5 {
  strings:
    $key_a7f5 = { f3 9d [2] 87 85 [2] c0 87 [2] 87 96 [2] c9 9a [2] c5 90 [2] d2 9b [2] c9 d5 [2] f4 }

  condition:
    any of them
}