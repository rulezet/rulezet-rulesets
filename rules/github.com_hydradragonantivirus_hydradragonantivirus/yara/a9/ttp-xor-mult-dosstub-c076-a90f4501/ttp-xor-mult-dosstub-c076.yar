rule TTP_XOR_MULT_DOSStub_c076 {
  strings:
    $key_c076 = { 94 1e [2] e0 06 [2] a7 04 [2] e0 15 [2] ae 19 [2] a2 13 [2] b5 18 [2] ae 56 [2] 93 }

  condition:
    any of them
}