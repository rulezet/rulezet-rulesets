rule TTP_XOR_MULT_DOSStub_028b {
  strings:
    $key_028b = { 56 e3 [2] 22 fb [2] 65 f9 [2] 22 e8 [2] 6c e4 [2] 60 ee [2] 77 e5 [2] 6c ab [2] 51 }

  condition:
    any of them
}