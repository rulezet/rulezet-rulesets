rule TTP_XOR_MULT_DOSStub_a273 {
  strings:
    $key_a273 = { f6 1b [2] 82 03 [2] c5 01 [2] 82 10 [2] cc 1c [2] c0 16 [2] d7 1d [2] cc 53 [2] f1 }

  condition:
    any of them
}