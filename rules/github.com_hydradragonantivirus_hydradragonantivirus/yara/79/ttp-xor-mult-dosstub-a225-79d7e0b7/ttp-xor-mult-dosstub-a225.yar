rule TTP_XOR_MULT_DOSStub_a225 {
  strings:
    $key_a225 = { f6 4d [2] 82 55 [2] c5 57 [2] 82 46 [2] cc 4a [2] c0 40 [2] d7 4b [2] cc 05 [2] f1 }

  condition:
    any of them
}