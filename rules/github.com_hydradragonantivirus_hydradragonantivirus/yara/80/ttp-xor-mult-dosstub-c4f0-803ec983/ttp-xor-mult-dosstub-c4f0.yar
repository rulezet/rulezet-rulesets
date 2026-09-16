rule TTP_XOR_MULT_DOSStub_c4f0 {
  strings:
    $key_c4f0 = { 90 98 [2] e4 80 [2] a3 82 [2] e4 93 [2] aa 9f [2] a6 95 [2] b1 9e [2] aa d0 [2] 97 }

  condition:
    any of them
}