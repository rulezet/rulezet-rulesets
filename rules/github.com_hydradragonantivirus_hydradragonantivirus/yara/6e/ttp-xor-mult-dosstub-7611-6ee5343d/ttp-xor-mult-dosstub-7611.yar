rule TTP_XOR_MULT_DOSStub_7611 {
  strings:
    $key_7611 = { 22 79 [2] 56 61 [2] 11 63 [2] 56 72 [2] 18 7e [2] 14 74 [2] 03 7f [2] 18 31 [2] 25 }

  condition:
    any of them
}