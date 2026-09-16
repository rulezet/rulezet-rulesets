rule TTP_XOR_MULT_DOSStub_1a00 {
  strings:
    $key_1a00 = { 4e 68 [2] 3a 70 [2] 7d 72 [2] 3a 63 [2] 74 6f [2] 78 65 [2] 6f 6e [2] 74 20 [2] 49 }

  condition:
    any of them
}