rule TTP_XOR_MULT_DOSStub_458d {
  strings:
    $key_458d = { 11 e5 [2] 65 fd [2] 22 ff [2] 65 ee [2] 2b e2 [2] 27 e8 [2] 30 e3 [2] 2b ad [2] 16 }

  condition:
    any of them
}