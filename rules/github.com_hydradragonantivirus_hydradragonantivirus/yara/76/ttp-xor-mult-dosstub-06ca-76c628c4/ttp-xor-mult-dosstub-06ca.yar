rule TTP_XOR_MULT_DOSStub_06ca {
  strings:
    $key_06ca = { 52 a2 [2] 26 ba [2] 61 b8 [2] 26 a9 [2] 68 a5 [2] 64 af [2] 73 a4 [2] 68 ea [2] 55 }

  condition:
    any of them
}