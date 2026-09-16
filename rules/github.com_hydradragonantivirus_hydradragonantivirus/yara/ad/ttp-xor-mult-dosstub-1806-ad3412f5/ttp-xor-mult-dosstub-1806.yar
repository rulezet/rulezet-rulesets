rule TTP_XOR_MULT_DOSStub_1806 {
  strings:
    $key_1806 = { 4c 6e [2] 38 76 [2] 7f 74 [2] 38 65 [2] 76 69 [2] 7a 63 [2] 6d 68 [2] 76 26 [2] 4b }

  condition:
    any of them
}