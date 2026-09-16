rule TTP_XOR_MULT_DOSStub_c367 {
  strings:
    $key_c367 = { 97 0f [2] e3 17 [2] a4 15 [2] e3 04 [2] ad 08 [2] a1 02 [2] b6 09 [2] ad 47 [2] 90 }

  condition:
    any of them
}