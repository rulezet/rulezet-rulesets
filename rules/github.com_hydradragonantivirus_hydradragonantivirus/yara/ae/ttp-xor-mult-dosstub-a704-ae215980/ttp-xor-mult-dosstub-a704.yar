rule TTP_XOR_MULT_DOSStub_a704 {
  strings:
    $key_a704 = { f3 6c [2] 87 74 [2] c0 76 [2] 87 67 [2] c9 6b [2] c5 61 [2] d2 6a [2] c9 24 [2] f4 }

  condition:
    any of them
}