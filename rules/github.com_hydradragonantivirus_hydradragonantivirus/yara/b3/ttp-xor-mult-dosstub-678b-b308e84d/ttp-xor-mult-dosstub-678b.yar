rule TTP_XOR_MULT_DOSStub_678b {
  strings:
    $key_678b = { 33 e3 [2] 47 fb [2] 00 f9 [2] 47 e8 [2] 09 e4 [2] 05 ee [2] 12 e5 [2] 09 ab [2] 34 }

  condition:
    any of them
}