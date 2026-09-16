rule TTP_XOR_MULT_DOSStub_c026 {
  strings:
    $key_c026 = { 94 4e [2] e0 56 [2] a7 54 [2] e0 45 [2] ae 49 [2] a2 43 [2] b5 48 [2] ae 06 [2] 93 }

  condition:
    any of them
}