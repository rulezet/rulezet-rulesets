rule TTP_XOR_MULT_DOSStub_c145 {
  strings:
    $key_c145 = { 95 2d [2] e1 35 [2] a6 37 [2] e1 26 [2] af 2a [2] a3 20 [2] b4 2b [2] af 65 [2] 92 }

  condition:
    any of them
}