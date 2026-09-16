rule TTP_XOR_MULT_DOSStub_62ca {
  strings:
    $key_62ca = { 36 a2 [2] 42 ba [2] 05 b8 [2] 42 a9 [2] 0c a5 [2] 00 af [2] 17 a4 [2] 0c ea [2] 31 }

  condition:
    any of them
}