rule TTP_XOR_MULT_DOSStub_a28e {
  strings:
    $key_a28e = { f6 e6 [2] 82 fe [2] c5 fc [2] 82 ed [2] cc e1 [2] c0 eb [2] d7 e0 [2] cc ae [2] f1 }

  condition:
    any of them
}