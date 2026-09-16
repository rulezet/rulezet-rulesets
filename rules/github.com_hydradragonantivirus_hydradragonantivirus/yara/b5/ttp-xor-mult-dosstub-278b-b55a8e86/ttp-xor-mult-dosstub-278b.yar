rule TTP_XOR_MULT_DOSStub_278b {
  strings:
    $key_278b = { 73 e3 [2] 07 fb [2] 40 f9 [2] 07 e8 [2] 49 e4 [2] 45 ee [2] 52 e5 [2] 49 ab [2] 74 }

  condition:
    any of them
}