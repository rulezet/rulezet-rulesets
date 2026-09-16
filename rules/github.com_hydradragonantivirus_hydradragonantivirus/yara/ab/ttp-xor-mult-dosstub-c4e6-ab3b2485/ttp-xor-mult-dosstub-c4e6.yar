rule TTP_XOR_MULT_DOSStub_c4e6 {
  strings:
    $key_c4e6 = { 90 8e [2] e4 96 [2] a3 94 [2] e4 85 [2] aa 89 [2] a6 83 [2] b1 88 [2] aa c6 [2] 97 }

  condition:
    any of them
}