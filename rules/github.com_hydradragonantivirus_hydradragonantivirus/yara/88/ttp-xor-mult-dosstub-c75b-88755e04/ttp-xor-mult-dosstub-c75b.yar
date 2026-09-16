rule TTP_XOR_MULT_DOSStub_c75b {
  strings:
    $key_c75b = { 93 33 [2] e7 2b [2] a0 29 [2] e7 38 [2] a9 34 [2] a5 3e [2] b2 35 [2] a9 7b [2] 94 }

  condition:
    any of them
}