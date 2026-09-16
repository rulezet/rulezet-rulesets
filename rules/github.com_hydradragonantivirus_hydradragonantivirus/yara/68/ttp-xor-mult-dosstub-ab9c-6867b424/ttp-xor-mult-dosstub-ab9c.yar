rule TTP_XOR_MULT_DOSStub_ab9c {
  strings:
    $key_ab9c = { ff f4 [2] 8b ec [2] cc ee [2] 8b ff [2] c5 f3 [2] c9 f9 [2] de f2 [2] c5 bc [2] f8 }

  condition:
    any of them
}