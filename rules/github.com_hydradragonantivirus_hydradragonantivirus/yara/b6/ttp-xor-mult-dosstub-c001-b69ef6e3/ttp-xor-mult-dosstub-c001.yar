rule TTP_XOR_MULT_DOSStub_c001 {
  strings:
    $key_c001 = { 94 69 [2] e0 71 [2] a7 73 [2] e0 62 [2] ae 6e [2] a2 64 [2] b5 6f [2] ae 21 [2] 93 }

  condition:
    any of them
}