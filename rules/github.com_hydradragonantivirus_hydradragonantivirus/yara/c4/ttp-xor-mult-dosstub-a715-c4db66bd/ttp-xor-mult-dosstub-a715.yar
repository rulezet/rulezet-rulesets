rule TTP_XOR_MULT_DOSStub_a715 {
  strings:
    $key_a715 = { f3 7d [2] 87 65 [2] c0 67 [2] 87 76 [2] c9 7a [2] c5 70 [2] d2 7b [2] c9 35 [2] f4 }

  condition:
    any of them
}