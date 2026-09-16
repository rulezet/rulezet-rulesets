rule TTP_XOR_MULT_DOSStub_c77e {
  strings:
    $key_c77e = { 93 16 [2] e7 0e [2] a0 0c [2] e7 1d [2] a9 11 [2] a5 1b [2] b2 10 [2] a9 5e [2] 94 }

  condition:
    any of them
}