rule TTP_XOR_MULT_DOSStub_45ca {
  strings:
    $key_45ca = { 11 a2 [2] 65 ba [2] 22 b8 [2] 65 a9 [2] 2b a5 [2] 27 af [2] 30 a4 [2] 2b ea [2] 16 }

  condition:
    any of them
}