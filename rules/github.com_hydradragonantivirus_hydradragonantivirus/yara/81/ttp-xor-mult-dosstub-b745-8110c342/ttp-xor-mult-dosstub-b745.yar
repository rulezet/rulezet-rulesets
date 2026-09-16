rule TTP_XOR_MULT_DOSStub_b745 {
  strings:
    $key_b745 = { e3 2d [2] 97 35 [2] d0 37 [2] 97 26 [2] d9 2a [2] d5 20 [2] c2 2b [2] d9 65 [2] e4 }

  condition:
    any of them
}