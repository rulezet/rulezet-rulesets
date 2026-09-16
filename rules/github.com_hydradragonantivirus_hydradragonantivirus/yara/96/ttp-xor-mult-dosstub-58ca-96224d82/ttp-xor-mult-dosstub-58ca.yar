rule TTP_XOR_MULT_DOSStub_58ca {
  strings:
    $key_58ca = { 0c a2 [2] 78 ba [2] 3f b8 [2] 78 a9 [2] 36 a5 [2] 3a af [2] 2d a4 [2] 36 ea [2] 0b }

  condition:
    any of them
}