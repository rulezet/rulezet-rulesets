rule TTP_XOR_MULT_DOSStub_1a06 {
  strings:
    $key_1a06 = { 4e 6e [2] 3a 76 [2] 7d 74 [2] 3a 65 [2] 74 69 [2] 78 63 [2] 6f 68 [2] 74 26 [2] 49 }

  condition:
    any of them
}