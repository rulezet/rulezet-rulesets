rule TTP_XOR_MULT_DOSStub_a274 {
  strings:
    $key_a274 = { f6 1c [2] 82 04 [2] c5 06 [2] 82 17 [2] cc 1b [2] c0 11 [2] d7 1a [2] cc 54 [2] f1 }

  condition:
    any of them
}