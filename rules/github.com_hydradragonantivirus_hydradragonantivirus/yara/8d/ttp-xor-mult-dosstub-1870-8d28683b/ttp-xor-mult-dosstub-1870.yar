rule TTP_XOR_MULT_DOSStub_1870 {
  strings:
    $key_1870 = { 4c 18 [2] 38 00 [2] 7f 02 [2] 38 13 [2] 76 1f [2] 7a 15 [2] 6d 1e [2] 76 50 [2] 4b }

  condition:
    any of them
}