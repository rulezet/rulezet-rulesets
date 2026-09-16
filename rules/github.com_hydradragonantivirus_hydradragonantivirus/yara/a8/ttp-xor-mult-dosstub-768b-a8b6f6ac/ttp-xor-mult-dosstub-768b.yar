rule TTP_XOR_MULT_DOSStub_768b {
  strings:
    $key_768b = { 22 e3 [2] 56 fb [2] 11 f9 [2] 56 e8 [2] 18 e4 [2] 14 ee [2] 03 e5 [2] 18 ab [2] 25 }

  condition:
    any of them
}