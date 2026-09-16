rule TTP_XOR_MULT_DOSStub_c449 {
  strings:
    $key_c449 = { 90 21 [2] e4 39 [2] a3 3b [2] e4 2a [2] aa 26 [2] a6 2c [2] b1 27 [2] aa 69 [2] 97 }

  condition:
    any of them
}