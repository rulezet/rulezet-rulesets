rule TTP_XOR_MULT_DOSStub_c00a {
  strings:
    $key_c00a = { 94 62 [2] e0 7a [2] a7 78 [2] e0 69 [2] ae 65 [2] a2 6f [2] b5 64 [2] ae 2a [2] 93 }

  condition:
    any of them
}