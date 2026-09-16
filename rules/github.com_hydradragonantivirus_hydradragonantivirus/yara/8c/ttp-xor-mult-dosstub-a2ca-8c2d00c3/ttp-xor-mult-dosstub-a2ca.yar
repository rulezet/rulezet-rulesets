rule TTP_XOR_MULT_DOSStub_a2ca {
  strings:
    $key_a2ca = { f6 a2 [2] 82 ba [2] c5 b8 [2] 82 a9 [2] cc a5 [2] c0 af [2] d7 a4 [2] cc ea [2] f1 }

  condition:
    any of them
}