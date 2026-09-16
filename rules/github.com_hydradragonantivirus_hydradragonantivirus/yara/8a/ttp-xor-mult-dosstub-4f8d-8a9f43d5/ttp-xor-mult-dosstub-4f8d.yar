rule TTP_XOR_MULT_DOSStub_4f8d {
  strings:
    $key_4f8d = { 1b e5 [2] 6f fd [2] 28 ff [2] 6f ee [2] 21 e2 [2] 2d e8 [2] 3a e3 [2] 21 ad [2] 1c }

  condition:
    any of them
}