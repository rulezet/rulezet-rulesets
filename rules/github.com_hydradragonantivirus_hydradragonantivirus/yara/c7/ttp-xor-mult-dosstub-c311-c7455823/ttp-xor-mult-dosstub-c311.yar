rule TTP_XOR_MULT_DOSStub_c311 {
  strings:
    $key_c311 = { 97 79 [2] e3 61 [2] a4 63 [2] e3 72 [2] ad 7e [2] a1 74 [2] b6 7f [2] ad 31 [2] 90 }

  condition:
    any of them
}