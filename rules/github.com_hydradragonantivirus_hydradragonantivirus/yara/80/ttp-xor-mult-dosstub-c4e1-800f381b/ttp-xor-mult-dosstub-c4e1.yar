rule TTP_XOR_MULT_DOSStub_c4e1 {
  strings:
    $key_c4e1 = { 90 89 [2] e4 91 [2] a3 93 [2] e4 82 [2] aa 8e [2] a6 84 [2] b1 8f [2] aa c1 [2] 97 }

  condition:
    any of them
}