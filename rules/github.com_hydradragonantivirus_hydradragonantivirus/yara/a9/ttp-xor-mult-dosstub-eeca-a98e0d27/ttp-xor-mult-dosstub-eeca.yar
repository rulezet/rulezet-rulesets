rule TTP_XOR_MULT_DOSStub_eeca {
  strings:
    $key_eeca = { ba a2 [2] ce ba [2] 89 b8 [2] ce a9 [2] 80 a5 [2] 8c af [2] 9b a4 [2] 80 ea [2] bd }

  condition:
    any of them
}