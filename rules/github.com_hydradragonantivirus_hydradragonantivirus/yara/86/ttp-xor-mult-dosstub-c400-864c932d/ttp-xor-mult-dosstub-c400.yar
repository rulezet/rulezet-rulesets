rule TTP_XOR_MULT_DOSStub_c400 {
  strings:
    $key_c400 = { 90 68 [2] e4 70 [2] a3 72 [2] e4 63 [2] aa 6f [2] a6 65 [2] b1 6e [2] aa 20 [2] 97 }

  condition:
    any of them
}