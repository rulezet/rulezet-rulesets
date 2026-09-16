rule TTP_XOR_MULT_DOSStub_5006 {
  strings:
    $key_5006 = { 04 6e [2] 70 76 [2] 37 74 [2] 70 65 [2] 3e 69 [2] 32 63 [2] 25 68 [2] 3e 26 [2] 03 }

  condition:
    any of them
}