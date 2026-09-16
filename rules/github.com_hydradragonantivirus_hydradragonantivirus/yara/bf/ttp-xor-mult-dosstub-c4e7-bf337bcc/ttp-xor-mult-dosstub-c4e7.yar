rule TTP_XOR_MULT_DOSStub_c4e7 {
  strings:
    $key_c4e7 = { 90 8f [2] e4 97 [2] a3 95 [2] e4 84 [2] aa 88 [2] a6 82 [2] b1 89 [2] aa c7 [2] 97 }

  condition:
    any of them
}