rule TTP_XOR_MULT_DOSStub_c375 {
  strings:
    $key_c375 = { 97 1d [2] e3 05 [2] a4 07 [2] e3 16 [2] ad 1a [2] a1 10 [2] b6 1b [2] ad 55 [2] 90 }

  condition:
    any of them
}