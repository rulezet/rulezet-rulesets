rule TTP_XOR_MULT_DOSStub_c08b {
  strings:
    $key_c08b = { 94 e3 [2] e0 fb [2] a7 f9 [2] e0 e8 [2] ae e4 [2] a2 ee [2] b5 e5 [2] ae ab [2] 93 }

  condition:
    any of them
}