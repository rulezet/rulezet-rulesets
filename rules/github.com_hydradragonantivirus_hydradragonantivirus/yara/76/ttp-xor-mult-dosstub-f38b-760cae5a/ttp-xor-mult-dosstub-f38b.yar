rule TTP_XOR_MULT_DOSStub_f38b {
  strings:
    $key_f38b = { a7 e3 [2] d3 fb [2] 94 f9 [2] d3 e8 [2] 9d e4 [2] 91 ee [2] 86 e5 [2] 9d ab [2] a0 }

  condition:
    any of them
}