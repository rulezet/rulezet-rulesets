rule TTP_XOR_MULT_DOSStub_a287 {
  strings:
    $key_a287 = { f6 ef [2] 82 f7 [2] c5 f5 [2] 82 e4 [2] cc e8 [2] c0 e2 [2] d7 e9 [2] cc a7 [2] f1 }

  condition:
    any of them
}