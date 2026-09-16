rule TTP_XOR_MULT_DOSStub_ab85 {
  strings:
    $key_ab85 = { ff ed [2] 8b f5 [2] cc f7 [2] 8b e6 [2] c5 ea [2] c9 e0 [2] de eb [2] c5 a5 [2] f8 }

  condition:
    any of them
}