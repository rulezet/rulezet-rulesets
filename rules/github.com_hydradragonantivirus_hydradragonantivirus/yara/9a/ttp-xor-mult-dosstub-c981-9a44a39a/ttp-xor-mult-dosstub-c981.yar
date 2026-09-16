rule TTP_XOR_MULT_DOSStub_c981 {
  strings:
    $key_c981 = { 9d e9 [2] e9 f1 [2] ae f3 [2] e9 e2 [2] a7 ee [2] ab e4 [2] bc ef [2] a7 a1 [2] 9a }

  condition:
    any of them
}