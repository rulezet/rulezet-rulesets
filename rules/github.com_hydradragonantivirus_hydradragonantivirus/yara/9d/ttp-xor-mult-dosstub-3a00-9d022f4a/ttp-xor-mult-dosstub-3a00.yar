rule TTP_XOR_MULT_DOSStub_3a00 {
  strings:
    $key_3a00 = { 6e 68 [2] 1a 70 [2] 5d 72 [2] 1a 63 [2] 54 6f [2] 58 65 [2] 4f 6e [2] 54 20 [2] 69 }

  condition:
    any of them
}