rule TTP_XOR_MULT_DOSStub_a211 {
  strings:
    $key_a211 = { f6 79 [2] 82 61 [2] c5 63 [2] 82 72 [2] cc 7e [2] c0 74 [2] d7 7f [2] cc 31 [2] f1 }

  condition:
    any of them
}