rule TTP_XOR_MULT_DOSStub_c327 {
  strings:
    $key_c327 = { 97 4f [2] e3 57 [2] a4 55 [2] e3 44 [2] ad 48 [2] a1 42 [2] b6 49 [2] ad 07 [2] 90 }

  condition:
    any of them
}