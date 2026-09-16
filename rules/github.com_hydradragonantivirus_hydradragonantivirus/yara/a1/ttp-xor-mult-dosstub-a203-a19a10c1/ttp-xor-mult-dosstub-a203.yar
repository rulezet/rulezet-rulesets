rule TTP_XOR_MULT_DOSStub_a203 {
  strings:
    $key_a203 = { f6 6b [2] 82 73 [2] c5 71 [2] 82 60 [2] cc 6c [2] c0 66 [2] d7 6d [2] cc 23 [2] f1 }

  condition:
    any of them
}