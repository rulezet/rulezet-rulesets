rule TTP_XOR_MULT_DOSStub_c049 {
  strings:
    $key_c049 = { 94 21 [2] e0 39 [2] a7 3b [2] e0 2a [2] ae 26 [2] a2 2c [2] b5 27 [2] ae 69 [2] 93 }

  condition:
    any of them
}