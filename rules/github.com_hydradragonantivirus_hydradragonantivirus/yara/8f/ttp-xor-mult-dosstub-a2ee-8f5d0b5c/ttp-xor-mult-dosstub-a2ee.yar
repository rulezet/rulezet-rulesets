rule TTP_XOR_MULT_DOSStub_a2ee {
  strings:
    $key_a2ee = { f6 86 [2] 82 9e [2] c5 9c [2] 82 8d [2] cc 81 [2] c0 8b [2] d7 80 [2] cc ce [2] f1 }

  condition:
    any of them
}