rule TTP_XOR_MULT_DOSStub_7f8d {
  strings:
    $key_7f8d = { 2b e5 [2] 5f fd [2] 18 ff [2] 5f ee [2] 11 e2 [2] 1d e8 [2] 0a e3 [2] 11 ad [2] 2c }

  condition:
    any of them
}