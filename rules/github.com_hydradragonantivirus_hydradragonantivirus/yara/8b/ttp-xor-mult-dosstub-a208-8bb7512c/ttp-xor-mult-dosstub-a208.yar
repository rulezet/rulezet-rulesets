rule TTP_XOR_MULT_DOSStub_a208 {
  strings:
    $key_a208 = { f6 60 [2] 82 78 [2] c5 7a [2] 82 6b [2] cc 67 [2] c0 6d [2] d7 66 [2] cc 28 [2] f1 }

  condition:
    any of them
}