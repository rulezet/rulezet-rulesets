rule TTP_XOR_MULT_DOSStub_c356 {
  strings:
    $key_c356 = { 97 3e [2] e3 26 [2] a4 24 [2] e3 35 [2] ad 39 [2] a1 33 [2] b6 38 [2] ad 76 [2] 90 }

  condition:
    any of them
}