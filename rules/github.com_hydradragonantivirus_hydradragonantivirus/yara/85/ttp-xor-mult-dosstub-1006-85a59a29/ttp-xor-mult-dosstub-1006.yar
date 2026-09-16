rule TTP_XOR_MULT_DOSStub_1006 {
  strings:
    $key_1006 = { 44 6e [2] 30 76 [2] 77 74 [2] 30 65 [2] 7e 69 [2] 72 63 [2] 65 68 [2] 7e 26 [2] 43 }

  condition:
    any of them
}