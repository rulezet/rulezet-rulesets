rule TTP_XOR_MULT_DOSStub_5d06 {
  strings:
    $key_5d06 = { 09 6e [2] 7d 76 [2] 3a 74 [2] 7d 65 [2] 33 69 [2] 3f 63 [2] 28 68 [2] 33 26 [2] 0e }

  condition:
    any of them
}