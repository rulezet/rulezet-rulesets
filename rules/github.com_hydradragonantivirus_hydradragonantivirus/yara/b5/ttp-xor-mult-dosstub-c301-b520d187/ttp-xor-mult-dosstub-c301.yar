rule TTP_XOR_MULT_DOSStub_c301 {
  strings:
    $key_c301 = { 97 69 [2] e3 71 [2] a4 73 [2] e3 62 [2] ad 6e [2] a1 64 [2] b6 6f [2] ad 21 [2] 90 }

  condition:
    any of them
}