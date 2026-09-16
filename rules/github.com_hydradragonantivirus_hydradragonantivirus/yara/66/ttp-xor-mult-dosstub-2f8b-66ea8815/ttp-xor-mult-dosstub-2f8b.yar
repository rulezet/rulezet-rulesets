rule TTP_XOR_MULT_DOSStub_2f8b {
  strings:
    $key_2f8b = { 7b e3 [2] 0f fb [2] 48 f9 [2] 0f e8 [2] 41 e4 [2] 4d ee [2] 5a e5 [2] 41 ab [2] 7c }

  condition:
    any of them
}