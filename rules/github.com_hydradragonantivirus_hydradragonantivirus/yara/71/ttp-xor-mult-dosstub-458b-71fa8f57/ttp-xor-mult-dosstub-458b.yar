rule TTP_XOR_MULT_DOSStub_458b {
  strings:
    $key_458b = { 11 e3 [2] 65 fb [2] 22 f9 [2] 65 e8 [2] 2b e4 [2] 27 ee [2] 30 e5 [2] 2b ab [2] 16 }

  condition:
    any of them
}