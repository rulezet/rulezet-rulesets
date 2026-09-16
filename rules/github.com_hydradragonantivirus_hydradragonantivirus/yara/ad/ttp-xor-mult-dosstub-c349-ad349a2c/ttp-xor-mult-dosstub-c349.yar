rule TTP_XOR_MULT_DOSStub_c349 {
  strings:
    $key_c349 = { 97 21 [2] e3 39 [2] a4 3b [2] e3 2a [2] ad 26 [2] a1 2c [2] b6 27 [2] ad 69 [2] 90 }

  condition:
    any of them
}