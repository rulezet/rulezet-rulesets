rule TTP_XOR_MULT_DOSStub_a28d {
  strings:
    $key_a28d = { f6 e5 [2] 82 fd [2] c5 ff [2] 82 ee [2] cc e2 [2] c0 e8 [2] d7 e3 [2] cc ad [2] f1 }

  condition:
    any of them
}