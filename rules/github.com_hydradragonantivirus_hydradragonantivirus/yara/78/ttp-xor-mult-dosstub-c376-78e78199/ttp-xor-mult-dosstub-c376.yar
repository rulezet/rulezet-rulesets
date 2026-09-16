rule TTP_XOR_MULT_DOSStub_c376 {
  strings:
    $key_c376 = { 97 1e [2] e3 06 [2] a4 04 [2] e3 15 [2] ad 19 [2] a1 13 [2] b6 18 [2] ad 56 [2] 90 }

  condition:
    any of them
}