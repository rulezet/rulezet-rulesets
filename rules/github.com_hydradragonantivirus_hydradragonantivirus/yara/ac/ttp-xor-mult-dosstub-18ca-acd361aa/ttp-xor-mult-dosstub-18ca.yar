rule TTP_XOR_MULT_DOSStub_18ca {
  strings:
    $key_18ca = { 4c a2 [2] 38 ba [2] 7f b8 [2] 38 a9 [2] 76 a5 [2] 7a af [2] 6d a4 [2] 76 ea [2] 4b }

  condition:
    any of them
}