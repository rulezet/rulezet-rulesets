rule TTP_XOR_MULT_DOSStub_a23c {
  strings:
    $key_a23c = { f6 54 [2] 82 4c [2] c5 4e [2] 82 5f [2] cc 53 [2] c0 59 [2] d7 52 [2] cc 1c [2] f1 }

  condition:
    any of them
}