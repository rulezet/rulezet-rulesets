rule TTP_XOR_MULT_DOSStub_f58b {
  strings:
    $key_f58b = { a1 e3 [2] d5 fb [2] 92 f9 [2] d5 e8 [2] 9b e4 [2] 97 ee [2] 80 e5 [2] 9b ab [2] a6 }

  condition:
    any of them
}