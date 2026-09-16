rule TTP_XOR_MULT_DOSStub_c072 {
  strings:
    $key_c072 = { 94 1a [2] e0 02 [2] a7 00 [2] e0 11 [2] ae 1d [2] a2 17 [2] b5 1c [2] ae 52 [2] 93 }

  condition:
    any of them
}