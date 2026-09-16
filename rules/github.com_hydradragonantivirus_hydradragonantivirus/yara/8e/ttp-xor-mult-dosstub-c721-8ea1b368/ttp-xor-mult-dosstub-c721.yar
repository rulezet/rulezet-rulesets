rule TTP_XOR_MULT_DOSStub_c721 {
  strings:
    $key_c721 = { 93 49 [2] e7 51 [2] a0 53 [2] e7 42 [2] a9 4e [2] a5 44 [2] b2 4f [2] a9 01 [2] 94 }

  condition:
    any of them
}