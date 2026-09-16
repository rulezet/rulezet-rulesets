rule TTP_XOR_MULT_DOSStub_a20b {
  strings:
    $key_a20b = { f6 63 [2] 82 7b [2] c5 79 [2] 82 68 [2] cc 64 [2] c0 6e [2] d7 65 [2] cc 2b [2] f1 }

  condition:
    any of them
}