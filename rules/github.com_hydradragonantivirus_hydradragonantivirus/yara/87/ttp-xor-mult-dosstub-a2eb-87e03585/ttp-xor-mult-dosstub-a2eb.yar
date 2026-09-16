rule TTP_XOR_MULT_DOSStub_a2eb {
  strings:
    $key_a2eb = { f6 83 [2] 82 9b [2] c5 99 [2] 82 88 [2] cc 84 [2] c0 8e [2] d7 85 [2] cc cb [2] f1 }

  condition:
    any of them
}