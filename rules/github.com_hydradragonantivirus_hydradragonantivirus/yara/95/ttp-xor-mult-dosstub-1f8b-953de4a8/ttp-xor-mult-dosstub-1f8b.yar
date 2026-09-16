rule TTP_XOR_MULT_DOSStub_1f8b {
  strings:
    $key_1f8b = { 4b e3 [2] 3f fb [2] 78 f9 [2] 3f e8 [2] 71 e4 [2] 7d ee [2] 6a e5 [2] 71 ab [2] 4c }

  condition:
    any of them
}