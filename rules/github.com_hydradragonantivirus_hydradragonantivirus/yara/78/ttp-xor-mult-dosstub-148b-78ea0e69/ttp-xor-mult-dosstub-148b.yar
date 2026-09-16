rule TTP_XOR_MULT_DOSStub_148b {
  strings:
    $key_148b = { 40 e3 [2] 34 fb [2] 73 f9 [2] 34 e8 [2] 7a e4 [2] 76 ee [2] 61 e5 [2] 7a ab [2] 47 }

  condition:
    any of them
}