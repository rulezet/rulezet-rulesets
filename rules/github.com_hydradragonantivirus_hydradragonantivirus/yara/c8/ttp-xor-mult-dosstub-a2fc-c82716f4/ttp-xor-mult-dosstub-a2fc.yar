rule TTP_XOR_MULT_DOSStub_a2fc {
  strings:
    $key_a2fc = { f6 94 [2] 82 8c [2] c5 8e [2] 82 9f [2] cc 93 [2] c0 99 [2] d7 92 [2] cc dc [2] f1 }

  condition:
    any of them
}