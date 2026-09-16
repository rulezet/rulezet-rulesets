rule TTP_XOR_MULT_DOSStub_6f8d {
  strings:
    $key_6f8d = { 3b e5 [2] 4f fd [2] 08 ff [2] 4f ee [2] 01 e2 [2] 0d e8 [2] 1a e3 [2] 01 ad [2] 3c }

  condition:
    any of them
}