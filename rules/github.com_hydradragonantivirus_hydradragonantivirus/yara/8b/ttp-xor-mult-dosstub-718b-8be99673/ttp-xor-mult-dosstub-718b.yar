rule TTP_XOR_MULT_DOSStub_718b {
  strings:
    $key_718b = { 25 e3 [2] 51 fb [2] 16 f9 [2] 51 e8 [2] 1f e4 [2] 13 ee [2] 04 e5 [2] 1f ab [2] 22 }

  condition:
    any of them
}