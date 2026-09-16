rule TTP_XOR_MULT_DOSStub_c04b {
  strings:
    $key_c04b = { 94 23 [2] e0 3b [2] a7 39 [2] e0 28 [2] ae 24 [2] a2 2e [2] b5 25 [2] ae 6b [2] 93 }

  condition:
    any of them
}