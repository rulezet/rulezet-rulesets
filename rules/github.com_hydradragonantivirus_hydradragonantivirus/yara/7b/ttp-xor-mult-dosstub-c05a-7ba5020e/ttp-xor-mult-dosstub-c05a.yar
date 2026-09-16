rule TTP_XOR_MULT_DOSStub_c05a {
  strings:
    $key_c05a = { 94 32 [2] e0 2a [2] a7 28 [2] e0 39 [2] ae 35 [2] a2 3f [2] b5 34 [2] ae 7a [2] 93 }

  condition:
    any of them
}