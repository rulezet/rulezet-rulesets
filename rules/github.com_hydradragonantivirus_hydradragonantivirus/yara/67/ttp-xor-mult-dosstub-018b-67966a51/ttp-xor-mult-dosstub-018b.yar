rule TTP_XOR_MULT_DOSStub_018b {
  strings:
    $key_018b = { 55 e3 [2] 21 fb [2] 66 f9 [2] 21 e8 [2] 6f e4 [2] 63 ee [2] 74 e5 [2] 6f ab [2] 52 }

  condition:
    any of them
}