rule TTP_XOR_MULT_DOSStub_229a {
  strings:
    $key_229a = { 76 f2 [2] 02 ea [2] 45 e8 [2] 02 f9 [2] 4c f5 [2] 40 ff [2] 57 f4 [2] 4c ba [2] 71 }

  condition:
    any of them
}