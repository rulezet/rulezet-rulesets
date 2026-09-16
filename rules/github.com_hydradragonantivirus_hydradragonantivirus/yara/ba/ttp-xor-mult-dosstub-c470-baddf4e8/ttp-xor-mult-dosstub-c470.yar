rule TTP_XOR_MULT_DOSStub_c470 {
  strings:
    $key_c470 = { 90 18 [2] e4 00 [2] a3 02 [2] e4 13 [2] aa 1f [2] a6 15 [2] b1 1e [2] aa 50 [2] 97 }

  condition:
    any of them
}