rule TTP_XOR_MULT_DOSStub_c006 {
  strings:
    $key_c006 = { 94 6e [2] e0 76 [2] a7 74 [2] e0 65 [2] ae 69 [2] a2 63 [2] b5 68 [2] ae 26 [2] 93 }

  condition:
    any of them
}