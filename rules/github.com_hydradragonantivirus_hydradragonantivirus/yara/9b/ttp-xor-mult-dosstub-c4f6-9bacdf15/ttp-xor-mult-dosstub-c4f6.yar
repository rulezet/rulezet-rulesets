rule TTP_XOR_MULT_DOSStub_c4f6 {
  strings:
    $key_c4f6 = { 90 9e [2] e4 86 [2] a3 84 [2] e4 95 [2] aa 99 [2] a6 93 [2] b1 98 [2] aa d6 [2] 97 }

  condition:
    any of them
}