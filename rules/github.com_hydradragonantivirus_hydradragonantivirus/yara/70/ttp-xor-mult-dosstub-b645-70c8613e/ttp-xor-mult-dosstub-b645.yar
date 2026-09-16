rule TTP_XOR_MULT_DOSStub_b645 {
  strings:
    $key_b645 = { e2 2d [2] 96 35 [2] d1 37 [2] 96 26 [2] d8 2a [2] d4 20 [2] c3 2b [2] d8 65 [2] e5 }

  condition:
    any of them
}