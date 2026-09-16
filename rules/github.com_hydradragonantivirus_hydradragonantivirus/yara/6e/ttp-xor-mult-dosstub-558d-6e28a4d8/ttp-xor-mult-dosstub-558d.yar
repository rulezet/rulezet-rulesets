rule TTP_XOR_MULT_DOSStub_558d {
  strings:
    $key_558d = { 01 e5 [2] 75 fd [2] 32 ff [2] 75 ee [2] 3b e2 [2] 37 e8 [2] 20 e3 [2] 3b ad [2] 06 }

  condition:
    any of them
}