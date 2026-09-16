rule TTP_XOR_MULT_DOSStub_c01a {
  strings:
    $key_c01a = { 94 72 [2] e0 6a [2] a7 68 [2] e0 79 [2] ae 75 [2] a2 7f [2] b5 74 [2] ae 3a [2] 93 }

  condition:
    any of them
}