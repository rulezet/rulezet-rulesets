rule TTP_XOR_MULT_DOSStub_058d {
  strings:
    $key_058d = { 51 e5 [2] 25 fd [2] 62 ff [2] 25 ee [2] 6b e2 [2] 67 e8 [2] 70 e3 [2] 6b ad [2] 56 }

  condition:
    any of them
}