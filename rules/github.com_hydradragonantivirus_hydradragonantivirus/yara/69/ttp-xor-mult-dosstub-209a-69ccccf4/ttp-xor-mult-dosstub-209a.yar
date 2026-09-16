rule TTP_XOR_MULT_DOSStub_209a {
  strings:
    $key_209a = { 74 f2 [2] 00 ea [2] 47 e8 [2] 00 f9 [2] 4e f5 [2] 42 ff [2] 55 f4 [2] 4e ba [2] 73 }

  condition:
    any of them
}