rule TTP_XOR_MULT_DOSStub_3f8d {
  strings:
    $key_3f8d = { 6b e5 [2] 1f fd [2] 58 ff [2] 1f ee [2] 51 e2 [2] 5d e8 [2] 4a e3 [2] 51 ad [2] 6c }

  condition:
    any of them
}