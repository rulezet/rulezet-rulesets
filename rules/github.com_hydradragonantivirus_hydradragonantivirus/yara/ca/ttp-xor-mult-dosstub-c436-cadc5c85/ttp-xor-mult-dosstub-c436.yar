rule TTP_XOR_MULT_DOSStub_c436 {
  strings:
    $key_c436 = { 90 5e [2] e4 46 [2] a3 44 [2] e4 55 [2] aa 59 [2] a6 53 [2] b1 58 [2] aa 16 [2] 97 }

  condition:
    any of them
}