rule TTP_XOR_MULT_DOSStub_728b {
  strings:
    $key_728b = { 26 e3 [2] 52 fb [2] 15 f9 [2] 52 e8 [2] 1c e4 [2] 10 ee [2] 07 e5 [2] 1c ab [2] 21 }

  condition:
    any of them
}