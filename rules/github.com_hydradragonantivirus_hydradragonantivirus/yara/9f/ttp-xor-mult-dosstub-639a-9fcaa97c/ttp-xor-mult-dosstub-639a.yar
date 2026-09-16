rule TTP_XOR_MULT_DOSStub_639a {
  strings:
    $key_639a = { 37 f2 [2] 43 ea [2] 04 e8 [2] 43 f9 [2] 0d f5 [2] 01 ff [2] 16 f4 [2] 0d ba [2] 30 }

  condition:
    any of them
}