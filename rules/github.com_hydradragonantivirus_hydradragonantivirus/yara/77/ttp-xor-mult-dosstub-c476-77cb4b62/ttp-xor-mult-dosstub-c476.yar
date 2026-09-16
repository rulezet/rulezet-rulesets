rule TTP_XOR_MULT_DOSStub_c476 {
  strings:
    $key_c476 = { 90 1e [2] e4 06 [2] a3 04 [2] e4 15 [2] aa 19 [2] a6 13 [2] b1 18 [2] aa 56 [2] 97 }

  condition:
    any of them
}