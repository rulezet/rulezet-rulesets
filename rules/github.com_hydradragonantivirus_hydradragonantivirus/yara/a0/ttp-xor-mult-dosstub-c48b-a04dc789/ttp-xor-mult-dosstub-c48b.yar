rule TTP_XOR_MULT_DOSStub_c48b {
  strings:
    $key_c48b = { 90 e3 [2] e4 fb [2] a3 f9 [2] e4 e8 [2] aa e4 [2] a6 ee [2] b1 e5 [2] aa ab [2] 97 }

  condition:
    any of them
}