rule TTP_XOR_MULT_DOSStub_c73e {
  strings:
    $key_c73e = { 93 56 [2] e7 4e [2] a0 4c [2] e7 5d [2] a9 51 [2] a5 5b [2] b2 50 [2] a9 1e [2] 94 }

  condition:
    any of them
}