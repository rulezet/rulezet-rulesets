rule TTP_XOR_MULT_DOSStub_c98b {
  strings:
    $key_c98b = { 9d e3 [2] e9 fb [2] ae f9 [2] e9 e8 [2] a7 e4 [2] ab ee [2] bc e5 [2] a7 ab [2] 9a }

  condition:
    any of them
}