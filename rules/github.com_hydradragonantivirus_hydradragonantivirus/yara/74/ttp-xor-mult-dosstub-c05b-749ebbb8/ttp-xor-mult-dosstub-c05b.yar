rule TTP_XOR_MULT_DOSStub_c05b {
  strings:
    $key_c05b = { 94 33 [2] e0 2b [2] a7 29 [2] e0 38 [2] ae 34 [2] a2 3e [2] b5 35 [2] ae 7b [2] 93 }

  condition:
    any of them
}