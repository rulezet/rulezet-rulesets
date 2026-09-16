rule TTP_XOR_MULT_DOSStub_1986 {
  strings:
    $key_1986 = { 4d ee [2] 39 f6 [2] 7e f4 [2] 39 e5 [2] 77 e9 [2] 7b e3 [2] 6c e8 [2] 77 a6 [2] 4a }

  condition:
    any of them
}