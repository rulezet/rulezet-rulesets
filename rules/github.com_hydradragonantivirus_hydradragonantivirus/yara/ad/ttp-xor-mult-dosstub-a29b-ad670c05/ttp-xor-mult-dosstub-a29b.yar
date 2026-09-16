rule TTP_XOR_MULT_DOSStub_a29b {
  strings:
    $key_a29b = { f6 f3 [2] 82 eb [2] c5 e9 [2] 82 f8 [2] cc f4 [2] c0 fe [2] d7 f5 [2] cc bb [2] f1 }

  condition:
    any of them
}