rule TTP_XOR_MULT_DOSStub_ab9a {
  strings:
    $key_ab9a = { ff f2 [2] 8b ea [2] cc e8 [2] 8b f9 [2] c5 f5 [2] c9 ff [2] de f4 [2] c5 ba [2] f8 }

  condition:
    any of them
}