rule TTP_XOR_MULT_DOSStub_3f8b {
  strings:
    $key_3f8b = { 6b e3 [2] 1f fb [2] 58 f9 [2] 1f e8 [2] 51 e4 [2] 5d ee [2] 4a e5 [2] 51 ab [2] 6c }

  condition:
    any of them
}