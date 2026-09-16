rule TTP_XOR_MULT_DOSStub_c471 {
  strings:
    $key_c471 = { 90 19 [2] e4 01 [2] a3 03 [2] e4 12 [2] aa 1e [2] a6 14 [2] b1 1f [2] aa 51 [2] 97 }

  condition:
    any of them
}