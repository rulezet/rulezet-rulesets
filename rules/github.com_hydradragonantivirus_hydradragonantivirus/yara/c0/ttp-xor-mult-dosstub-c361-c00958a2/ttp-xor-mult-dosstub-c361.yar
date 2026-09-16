rule TTP_XOR_MULT_DOSStub_c361 {
  strings:
    $key_c361 = { 97 09 [2] e3 11 [2] a4 13 [2] e3 02 [2] ad 0e [2] a1 04 [2] b6 0f [2] ad 41 [2] 90 }

  condition:
    any of them
}