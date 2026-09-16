rule TTP_XOR_MULT_DOSStub_c148 {
  strings:
    $key_c148 = { 95 20 [2] e1 38 [2] a6 3a [2] e1 2b [2] af 27 [2] a3 2d [2] b4 26 [2] af 68 [2] 92 }

  condition:
    any of them
}