rule TTP_XOR_MULT_DOSStub_7606 {
  strings:
    $key_7606 = { 22 6e [2] 56 76 [2] 11 74 [2] 56 65 [2] 18 69 [2] 14 63 [2] 03 68 [2] 18 26 [2] 25 }

  condition:
    any of them
}