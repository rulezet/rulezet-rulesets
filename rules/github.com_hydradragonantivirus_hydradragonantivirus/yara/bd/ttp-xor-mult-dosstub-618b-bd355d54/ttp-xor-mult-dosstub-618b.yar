rule TTP_XOR_MULT_DOSStub_618b {
  strings:
    $key_618b = { 35 e3 [2] 41 fb [2] 06 f9 [2] 41 e8 [2] 0f e4 [2] 03 ee [2] 14 e5 [2] 0f ab [2] 32 }

  condition:
    any of them
}