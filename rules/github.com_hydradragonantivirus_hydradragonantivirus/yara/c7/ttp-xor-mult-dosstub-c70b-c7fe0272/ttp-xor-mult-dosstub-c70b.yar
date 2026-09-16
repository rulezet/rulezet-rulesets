rule TTP_XOR_MULT_DOSStub_c70b {
  strings:
    $key_c70b = { 93 63 [2] e7 7b [2] a0 79 [2] e7 68 [2] a9 64 [2] a5 6e [2] b2 65 [2] a9 2b [2] 94 }

  condition:
    any of them
}