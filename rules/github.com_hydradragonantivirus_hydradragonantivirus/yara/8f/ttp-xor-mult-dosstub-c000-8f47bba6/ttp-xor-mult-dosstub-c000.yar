rule TTP_XOR_MULT_DOSStub_c000 {
  strings:
    $key_c000 = { 94 68 [2] e0 70 [2] a7 72 [2] e0 63 [2] ae 6f [2] a2 65 [2] b5 6e [2] ae 20 [2] 93 }

  condition:
    any of them
}