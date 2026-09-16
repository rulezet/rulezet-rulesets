rule TTP_XOR_MULT_DOSStub_c3e7 {
  strings:
    $key_c3e7 = { 97 8f [2] e3 97 [2] a4 95 [2] e3 84 [2] ad 88 [2] a1 82 [2] b6 89 [2] ad c7 [2] 90 }

  condition:
    any of them
}