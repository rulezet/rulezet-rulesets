rule TTP_XOR_MULT_DOSStub_28ca {
  strings:
    $key_28ca = { 7c a2 [2] 08 ba [2] 4f b8 [2] 08 a9 [2] 46 a5 [2] 4a af [2] 5d a4 [2] 46 ea [2] 7b }

  condition:
    any of them
}