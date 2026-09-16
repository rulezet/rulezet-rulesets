rule TTP_XOR_MULT_DOSStub_419a {
  strings:
    $key_419a = { 15 f2 [2] 61 ea [2] 26 e8 [2] 61 f9 [2] 2f f5 [2] 23 ff [2] 34 f4 [2] 2f ba [2] 12 }

  condition:
    any of them
}