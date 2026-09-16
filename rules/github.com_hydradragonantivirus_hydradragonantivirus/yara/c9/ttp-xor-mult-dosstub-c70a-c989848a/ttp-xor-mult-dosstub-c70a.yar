rule TTP_XOR_MULT_DOSStub_c70a {
  strings:
    $key_c70a = { 93 62 [2] e7 7a [2] a0 78 [2] e7 69 [2] a9 65 [2] a5 6f [2] b2 64 [2] a9 2a [2] 94 }

  condition:
    any of them
}