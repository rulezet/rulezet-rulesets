rule TTP_XOR_MULT_DOSStub_a713 {
  strings:
    $key_a713 = { f3 7b [2] 87 63 [2] c0 61 [2] 87 70 [2] c9 7c [2] c5 76 [2] d2 7d [2] c9 33 [2] f4 }

  condition:
    any of them
}