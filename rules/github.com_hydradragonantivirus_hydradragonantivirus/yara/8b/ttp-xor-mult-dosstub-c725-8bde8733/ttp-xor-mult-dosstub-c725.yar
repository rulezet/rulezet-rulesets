rule TTP_XOR_MULT_DOSStub_c725 {
  strings:
    $key_c725 = { 93 4d [2] e7 55 [2] a0 57 [2] e7 46 [2] a9 4a [2] a5 40 [2] b2 4b [2] a9 05 [2] 94 }

  condition:
    any of them
}