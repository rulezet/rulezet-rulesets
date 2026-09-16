rule TTP_XOR_MULT_DOSStub_c057 {
  strings:
    $key_c057 = { 94 3f [2] e0 27 [2] a7 25 [2] e0 34 [2] ae 38 [2] a2 32 [2] b5 39 [2] ae 77 [2] 93 }

  condition:
    any of them
}