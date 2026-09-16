rule TTP_XOR_MULT_DOSStub_c358 {
  strings:
    $key_c358 = { 97 30 [2] e3 28 [2] a4 2a [2] e3 3b [2] ad 37 [2] a1 3d [2] b6 36 [2] ad 78 [2] 90 }

  condition:
    any of them
}