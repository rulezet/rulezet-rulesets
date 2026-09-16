rule TTP_XOR_MULT_DOSStub_a2d4 {
  strings:
    $key_a2d4 = { f6 bc [2] 82 a4 [2] c5 a6 [2] 82 b7 [2] cc bb [2] c0 b1 [2] d7 ba [2] cc f4 [2] f1 }

  condition:
    any of them
}