rule TTP_XOR_MULT_DOSStub_11ca {
  strings:
    $key_11ca = { 45 a2 [2] 31 ba [2] 76 b8 [2] 31 a9 [2] 7f a5 [2] 73 af [2] 64 a4 [2] 7f ea [2] 42 }

  condition:
    any of them
}