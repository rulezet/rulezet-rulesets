rule TTP_XOR_MULT_DOSStub_c465 {
  strings:
    $key_c465 = { 90 0d [2] e4 15 [2] a3 17 [2] e4 06 [2] aa 0a [2] a6 00 [2] b1 0b [2] aa 45 [2] 97 }

  condition:
    any of them
}