rule TTP_XOR_MULT_DOSStub_109a {
  strings:
    $key_109a = { 44 f2 [2] 30 ea [2] 77 e8 [2] 30 f9 [2] 7e f5 [2] 72 ff [2] 65 f4 [2] 7e ba [2] 43 }

  condition:
    any of them
}