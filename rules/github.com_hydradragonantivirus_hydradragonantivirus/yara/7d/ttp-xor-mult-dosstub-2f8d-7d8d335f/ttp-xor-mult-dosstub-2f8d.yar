rule TTP_XOR_MULT_DOSStub_2f8d {
  strings:
    $key_2f8d = { 7b e5 [2] 0f fd [2] 48 ff [2] 0f ee [2] 41 e2 [2] 4d e8 [2] 5a e3 [2] 41 ad [2] 7c }

  condition:
    any of them
}