rule TTP_XOR_MULT_DOSStub_c027 {
  strings:
    $key_c027 = { 94 4f [2] e0 57 [2] a7 55 [2] e0 44 [2] ae 48 [2] a2 42 [2] b5 49 [2] ae 07 [2] 93 }

  condition:
    any of them
}