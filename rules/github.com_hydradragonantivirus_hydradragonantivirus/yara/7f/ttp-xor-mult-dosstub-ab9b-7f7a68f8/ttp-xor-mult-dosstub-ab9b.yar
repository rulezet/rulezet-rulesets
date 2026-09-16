rule TTP_XOR_MULT_DOSStub_ab9b {
  strings:
    $key_ab9b = { ff f3 [2] 8b eb [2] cc e9 [2] 8b f8 [2] c5 f4 [2] c9 fe [2] de f5 [2] c5 bb [2] f8 }

  condition:
    any of them
}