rule TTP_XOR_MULT_DOSStub_c158 {
  strings:
    $key_c158 = { 95 30 [2] e1 28 [2] a6 2a [2] e1 3b [2] af 37 [2] a3 3d [2] b4 36 [2] af 78 [2] 92 }

  condition:
    any of them
}