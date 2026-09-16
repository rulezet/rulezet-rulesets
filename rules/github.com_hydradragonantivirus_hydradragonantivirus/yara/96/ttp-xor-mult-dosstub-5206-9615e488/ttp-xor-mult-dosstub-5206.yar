rule TTP_XOR_MULT_DOSStub_5206 {
  strings:
    $key_5206 = { 06 6e [2] 72 76 [2] 35 74 [2] 72 65 [2] 3c 69 [2] 30 63 [2] 27 68 [2] 3c 26 [2] 01 }

  condition:
    any of them
}