rule TTP_XOR_MULT_DOSStub_ab96 {
  strings:
    $key_ab96 = { ff fe [2] 8b e6 [2] cc e4 [2] 8b f5 [2] c5 f9 [2] c9 f3 [2] de f8 [2] c5 b6 [2] f8 }

  condition:
    any of them
}