rule TTP_XOR_MULT_DOSStub_71ca {
  strings:
    $key_71ca = { 25 a2 [2] 51 ba [2] 16 b8 [2] 51 a9 [2] 1f a5 [2] 13 af [2] 04 a4 [2] 1f ea [2] 22 }

  condition:
    any of them
}