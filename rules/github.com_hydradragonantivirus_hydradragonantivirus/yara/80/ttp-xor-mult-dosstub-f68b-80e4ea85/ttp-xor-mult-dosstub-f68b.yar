rule TTP_XOR_MULT_DOSStub_f68b {
  strings:
    $key_f68b = { a2 e3 [2] d6 fb [2] 91 f9 [2] d6 e8 [2] 98 e4 [2] 94 ee [2] 83 e5 [2] 98 ab [2] a5 }

  condition:
    any of them
}