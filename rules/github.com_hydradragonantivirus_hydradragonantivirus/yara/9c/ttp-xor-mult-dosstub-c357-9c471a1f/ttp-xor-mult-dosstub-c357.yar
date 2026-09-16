rule TTP_XOR_MULT_DOSStub_c357 {
  strings:
    $key_c357 = { 97 3f [2] e3 27 [2] a4 25 [2] e3 34 [2] ad 38 [2] a1 32 [2] b6 39 [2] ad 77 [2] 90 }

  condition:
    any of them
}