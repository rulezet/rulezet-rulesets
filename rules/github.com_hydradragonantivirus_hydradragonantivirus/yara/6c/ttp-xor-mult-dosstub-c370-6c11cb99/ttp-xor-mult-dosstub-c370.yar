rule TTP_XOR_MULT_DOSStub_c370 {
  strings:
    $key_c370 = { 97 18 [2] e3 00 [2] a4 02 [2] e3 13 [2] ad 1f [2] a1 15 [2] b6 1e [2] ad 50 [2] 90 }

  condition:
    any of them
}