rule TTP_XOR_MULT_DOSStub_32ca {
  strings:
    $key_32ca = { 66 a2 [2] 12 ba [2] 55 b8 [2] 12 a9 [2] 5c a5 [2] 50 af [2] 47 a4 [2] 5c ea [2] 61 }

  condition:
    any of them
}