rule TTP_XOR_MULT_DOSStub_c04a {
  strings:
    $key_c04a = { 94 22 [2] e0 3a [2] a7 38 [2] e0 29 [2] ae 25 [2] a2 2f [2] b5 24 [2] ae 6a [2] 93 }

  condition:
    any of them
}