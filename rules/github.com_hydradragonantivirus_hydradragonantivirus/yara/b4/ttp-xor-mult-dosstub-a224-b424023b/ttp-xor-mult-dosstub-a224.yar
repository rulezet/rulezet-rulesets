rule TTP_XOR_MULT_DOSStub_a224 {
  strings:
    $key_a224 = { f6 4c [2] 82 54 [2] c5 56 [2] 82 47 [2] cc 4b [2] c0 41 [2] d7 4a [2] cc 04 [2] f1 }

  condition:
    any of them
}