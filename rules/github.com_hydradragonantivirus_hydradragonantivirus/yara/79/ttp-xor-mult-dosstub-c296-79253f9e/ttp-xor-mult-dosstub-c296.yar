rule TTP_XOR_MULT_DOSStub_c296 {
  strings:
    $key_c296 = { 96 fe [2] e2 e6 [2] a5 e4 [2] e2 f5 [2] ac f9 [2] a0 f3 [2] b7 f8 [2] ac b6 [2] 91 }

  condition:
    any of them
}