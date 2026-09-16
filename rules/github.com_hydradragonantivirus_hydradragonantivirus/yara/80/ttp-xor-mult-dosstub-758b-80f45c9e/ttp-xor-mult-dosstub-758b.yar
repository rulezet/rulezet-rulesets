rule TTP_XOR_MULT_DOSStub_758b {
  strings:
    $key_758b = { 21 e3 [2] 55 fb [2] 12 f9 [2] 55 e8 [2] 1b e4 [2] 17 ee [2] 00 e5 [2] 1b ab [2] 26 }

  condition:
    any of them
}