rule TTP_XOR_MULT_DOSStub_a227 {
  strings:
    $key_a227 = { f6 4f [2] 82 57 [2] c5 55 [2] 82 44 [2] cc 48 [2] c0 42 [2] d7 49 [2] cc 07 [2] f1 }

  condition:
    any of them
}