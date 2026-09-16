rule TTP_XOR_MULT_DOSStub_c142 {
  strings:
    $key_c142 = { 95 2a [2] e1 32 [2] a6 30 [2] e1 21 [2] af 2d [2] a3 27 [2] b4 2c [2] af 62 [2] 92 }

  condition:
    any of them
}