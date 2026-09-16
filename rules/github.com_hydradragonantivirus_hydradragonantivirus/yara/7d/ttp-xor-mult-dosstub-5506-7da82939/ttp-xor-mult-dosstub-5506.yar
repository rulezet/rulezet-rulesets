rule TTP_XOR_MULT_DOSStub_5506 {
  strings:
    $key_5506 = { 01 6e [2] 75 76 [2] 32 74 [2] 75 65 [2] 3b 69 [2] 37 63 [2] 20 68 [2] 3b 26 [2] 06 }

  condition:
    any of them
}