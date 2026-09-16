rule TTP_XOR_MULT_DOSStub_ab88 {
  strings:
    $key_ab88 = { ff e0 [2] 8b f8 [2] cc fa [2] 8b eb [2] c5 e7 [2] c9 ed [2] de e6 [2] c5 a8 [2] f8 }

  condition:
    any of them
}