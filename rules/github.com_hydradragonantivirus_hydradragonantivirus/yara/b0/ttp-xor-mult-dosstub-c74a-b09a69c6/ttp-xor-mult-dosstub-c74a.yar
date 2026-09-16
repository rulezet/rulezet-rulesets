rule TTP_XOR_MULT_DOSStub_c74a {
  strings:
    $key_c74a = { 93 22 [2] e7 3a [2] a0 38 [2] e7 29 [2] a9 25 [2] a5 2f [2] b2 24 [2] a9 6a [2] 94 }

  condition:
    any of them
}