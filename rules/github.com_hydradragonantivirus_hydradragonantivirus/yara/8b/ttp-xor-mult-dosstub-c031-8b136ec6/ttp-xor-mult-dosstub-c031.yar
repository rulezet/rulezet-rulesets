rule TTP_XOR_MULT_DOSStub_c031 {
  strings:
    $key_c031 = { 94 59 [2] e0 41 [2] a7 43 [2] e0 52 [2] ae 5e [2] a2 54 [2] b5 5f [2] ae 11 [2] 93 }

  condition:
    any of them
}