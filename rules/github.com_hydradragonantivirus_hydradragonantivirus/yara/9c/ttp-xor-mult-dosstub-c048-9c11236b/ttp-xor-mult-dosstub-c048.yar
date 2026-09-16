rule TTP_XOR_MULT_DOSStub_c048 {
  strings:
    $key_c048 = { 94 20 [2] e0 38 [2] a7 3a [2] e0 2b [2] ae 27 [2] a2 2d [2] b5 26 [2] ae 68 [2] 93 }

  condition:
    any of them
}