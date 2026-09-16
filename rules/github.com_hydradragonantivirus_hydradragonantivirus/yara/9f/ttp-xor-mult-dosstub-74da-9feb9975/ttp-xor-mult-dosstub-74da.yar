rule TTP_XOR_MULT_DOSStub_74da {
  strings:
    $key_74da = { 20 b2 [2] 54 aa [2] 13 a8 [2] 54 b9 [2] 1a b5 [2] 16 bf [2] 01 b4 [2] 1a fa [2] 27 }

  condition:
    any of them
}