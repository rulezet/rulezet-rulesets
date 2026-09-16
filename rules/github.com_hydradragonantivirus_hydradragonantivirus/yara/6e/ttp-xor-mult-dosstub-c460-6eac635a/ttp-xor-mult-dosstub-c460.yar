rule TTP_XOR_MULT_DOSStub_c460 {
  strings:
    $key_c460 = { 90 08 [2] e4 10 [2] a3 12 [2] e4 03 [2] aa 0f [2] a6 05 [2] b1 0e [2] aa 40 [2] 97 }

  condition:
    any of them
}