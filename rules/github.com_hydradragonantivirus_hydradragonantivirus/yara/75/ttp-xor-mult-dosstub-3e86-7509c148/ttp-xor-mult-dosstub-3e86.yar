rule TTP_XOR_MULT_DOSStub_3e86 {
  strings:
    $key_3e86 = { 6a ee [2] 1e f6 [2] 59 f4 [2] 1e e5 [2] 50 e9 [2] 5c e3 [2] 4b e8 [2] 50 a6 [2] 6d }

  condition:
    any of them
}