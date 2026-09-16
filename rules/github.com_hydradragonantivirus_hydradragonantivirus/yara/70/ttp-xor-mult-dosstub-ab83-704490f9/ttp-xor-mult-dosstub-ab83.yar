rule TTP_XOR_MULT_DOSStub_ab83 {
  strings:
    $key_ab83 = { ff eb [2] 8b f3 [2] cc f1 [2] 8b e0 [2] c5 ec [2] c9 e6 [2] de ed [2] c5 a3 [2] f8 }

  condition:
    any of them
}