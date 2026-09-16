rule TTP_XOR_MULT_DOSStub_768d {
  strings:
    $key_768d = { 22 e5 [2] 56 fd [2] 11 ff [2] 56 ee [2] 18 e2 [2] 14 e8 [2] 03 e3 [2] 18 ad [2] 25 }

  condition:
    any of them
}