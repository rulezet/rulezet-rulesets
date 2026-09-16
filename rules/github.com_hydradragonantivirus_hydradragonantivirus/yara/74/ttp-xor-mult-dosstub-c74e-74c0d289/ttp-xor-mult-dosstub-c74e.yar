rule TTP_XOR_MULT_DOSStub_c74e {
  strings:
    $key_c74e = { 93 26 [2] e7 3e [2] a0 3c [2] e7 2d [2] a9 21 [2] a5 2b [2] b2 20 [2] a9 6e [2] 94 }

  condition:
    any of them
}