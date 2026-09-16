rule TTP_XOR_MULT_DOSStub_35ca {
  strings:
    $key_35ca = { 61 a2 [2] 15 ba [2] 52 b8 [2] 15 a9 [2] 5b a5 [2] 57 af [2] 40 a4 [2] 5b ea [2] 66 }

  condition:
    any of them
}