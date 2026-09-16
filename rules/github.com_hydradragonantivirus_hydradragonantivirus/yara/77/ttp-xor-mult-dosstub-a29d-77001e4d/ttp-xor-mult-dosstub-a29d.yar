rule TTP_XOR_MULT_DOSStub_a29d {
  strings:
    $key_a29d = { f6 f5 [2] 82 ed [2] c5 ef [2] 82 fe [2] cc f2 [2] c0 f8 [2] d7 f3 [2] cc bd [2] f1 }

  condition:
    any of them
}