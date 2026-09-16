rule TTP_XOR_MULT_DOSStub_c3f7 {
  strings:
    $key_c3f7 = { 97 9f [2] e3 87 [2] a4 85 [2] e3 94 [2] ad 98 [2] a1 92 [2] b6 99 [2] ad d7 [2] 90 }

  condition:
    any of them
}