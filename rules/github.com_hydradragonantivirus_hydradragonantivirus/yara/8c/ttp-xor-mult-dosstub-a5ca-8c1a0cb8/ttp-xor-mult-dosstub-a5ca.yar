rule TTP_XOR_MULT_DOSStub_a5ca {
  strings:
    $key_a5ca = { f1 a2 [2] 85 ba [2] c2 b8 [2] 85 a9 [2] cb a5 [2] c7 af [2] d0 a4 [2] cb ea [2] f6 }

  condition:
    any of them
}