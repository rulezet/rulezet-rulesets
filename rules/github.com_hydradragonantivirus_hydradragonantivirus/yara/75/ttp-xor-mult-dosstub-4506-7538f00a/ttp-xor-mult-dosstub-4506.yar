rule TTP_XOR_MULT_DOSStub_4506 {
  strings:
    $key_4506 = { 11 6e [2] 65 76 [2] 22 74 [2] 65 65 [2] 2b 69 [2] 27 63 [2] 30 68 [2] 2b 26 [2] 16 }

  condition:
    any of them
}