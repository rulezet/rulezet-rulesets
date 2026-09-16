rule TTP_XOR_MULT_DOSStub_a22b {
  strings:
    $key_a22b = { f6 43 [2] 82 5b [2] c5 59 [2] 82 48 [2] cc 44 [2] c0 4e [2] d7 45 [2] cc 0b [2] f1 }

  condition:
    any of them
}