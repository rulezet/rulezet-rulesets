rule TTP_XOR_MULT_DOSStub_f08b {
  strings:
    $key_f08b = { a4 e3 [2] d0 fb [2] 97 f9 [2] d0 e8 [2] 9e e4 [2] 92 ee [2] 85 e5 [2] 9e ab [2] a3 }

  condition:
    any of them
}