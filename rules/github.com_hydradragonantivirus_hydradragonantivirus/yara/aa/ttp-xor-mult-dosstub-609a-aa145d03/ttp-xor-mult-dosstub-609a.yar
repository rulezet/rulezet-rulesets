rule TTP_XOR_MULT_DOSStub_609a {
  strings:
    $key_609a = { 34 f2 [2] 40 ea [2] 07 e8 [2] 40 f9 [2] 0e f5 [2] 02 ff [2] 15 f4 [2] 0e ba [2] 33 }

  condition:
    any of them
}