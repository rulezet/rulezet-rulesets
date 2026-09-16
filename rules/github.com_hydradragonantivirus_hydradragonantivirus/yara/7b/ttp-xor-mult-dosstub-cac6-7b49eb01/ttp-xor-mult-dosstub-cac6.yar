rule TTP_XOR_MULT_DOSStub_cac6 {
  strings:
    $key_cac6 = { 9e ae [2] ea b6 [2] ad b4 [2] ea a5 [2] a4 a9 [2] a8 a3 [2] bf a8 [2] a4 e6 [2] 99 }

  condition:
    any of them
}