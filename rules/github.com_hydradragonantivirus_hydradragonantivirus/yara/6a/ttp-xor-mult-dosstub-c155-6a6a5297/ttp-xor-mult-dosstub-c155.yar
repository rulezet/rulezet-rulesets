rule TTP_XOR_MULT_DOSStub_c155 {
  strings:
    $key_c155 = { 95 3d [2] e1 25 [2] a6 27 [2] e1 36 [2] af 3a [2] a3 30 [2] b4 3b [2] af 75 [2] 92 }

  condition:
    any of them
}