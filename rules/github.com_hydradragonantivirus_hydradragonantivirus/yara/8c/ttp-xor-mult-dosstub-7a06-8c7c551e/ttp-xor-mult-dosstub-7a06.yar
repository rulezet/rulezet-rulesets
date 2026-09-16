rule TTP_XOR_MULT_DOSStub_7a06 {
  strings:
    $key_7a06 = { 2e 6e [2] 5a 76 [2] 1d 74 [2] 5a 65 [2] 14 69 [2] 18 63 [2] 0f 68 [2] 14 26 [2] 29 }

  condition:
    any of them
}