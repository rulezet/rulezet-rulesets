rule TTP_XOR_MULT_DOSStub_c378 {
  strings:
    $key_c378 = { 97 10 [2] e3 08 [2] a4 0a [2] e3 1b [2] ad 17 [2] a1 1d [2] b6 16 [2] ad 58 [2] 90 }

  condition:
    any of them
}