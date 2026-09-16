rule TTP_XOR_MULT_DOSStub_fe8b {
  strings:
    $key_fe8b = { aa e3 [2] de fb [2] 99 f9 [2] de e8 [2] 90 e4 [2] 9c ee [2] 8b e5 [2] 90 ab [2] ad }

  condition:
    any of them
}