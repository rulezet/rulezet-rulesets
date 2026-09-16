rule TTP_XOR_MULT_DOSStub_c410 {
  strings:
    $key_c410 = { 90 78 [2] e4 60 [2] a3 62 [2] e4 73 [2] aa 7f [2] a6 75 [2] b1 7e [2] aa 30 [2] 97 }

  condition:
    any of them
}