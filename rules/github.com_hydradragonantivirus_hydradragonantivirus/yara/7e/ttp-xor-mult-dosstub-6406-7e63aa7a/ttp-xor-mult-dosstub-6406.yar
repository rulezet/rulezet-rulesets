rule TTP_XOR_MULT_DOSStub_6406 {
  strings:
    $key_6406 = { 30 6e [2] 44 76 [2] 03 74 [2] 44 65 [2] 0a 69 [2] 06 63 [2] 11 68 [2] 0a 26 [2] 37 }

  condition:
    any of them
}