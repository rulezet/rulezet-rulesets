rule TTP_XOR_MULT_DOSStub_8b82 {
  strings:
    $key_8b82 = { df ea [2] ab f2 [2] ec f0 [2] ab e1 [2] e5 ed [2] e9 e7 [2] fe ec [2] e5 a2 [2] d8 }

  condition:
    any of them
}