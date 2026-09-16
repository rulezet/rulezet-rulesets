rule TTP_XOR_MULT_DOSStub_c00b {
  strings:
    $key_c00b = { 94 63 [2] e0 7b [2] a7 79 [2] e0 68 [2] ae 64 [2] a2 6e [2] b5 65 [2] ae 2b [2] 93 }

  condition:
    any of them
}