rule TTP_XOR_MULT_DOSStub_149a {
  strings:
    $key_149a = { 40 f2 [2] 34 ea [2] 73 e8 [2] 34 f9 [2] 7a f5 [2] 76 ff [2] 61 f4 [2] 7a ba [2] 47 }

  condition:
    any of them
}