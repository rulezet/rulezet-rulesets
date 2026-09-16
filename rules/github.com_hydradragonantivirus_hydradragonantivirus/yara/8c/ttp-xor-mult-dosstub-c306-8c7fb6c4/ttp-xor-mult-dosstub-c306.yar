rule TTP_XOR_MULT_DOSStub_c306 {
  strings:
    $key_c306 = { 97 6e [2] e3 76 [2] a4 74 [2] e3 65 [2] ad 69 [2] a1 63 [2] b6 68 [2] ad 26 [2] 90 }

  condition:
    any of them
}