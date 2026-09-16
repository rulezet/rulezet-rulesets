rule TTP_XOR_MULT_DOSStub_a264 {
  strings:
    $key_a264 = { f6 0c [2] 82 14 [2] c5 16 [2] 82 07 [2] cc 0b [2] c0 01 [2] d7 0a [2] cc 44 [2] f1 }

  condition:
    any of them
}