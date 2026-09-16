rule TTP_XOR_MULT_DOSStub_7800 {
  strings:
    $key_7800 = { 2c 68 [2] 58 70 [2] 1f 72 [2] 58 63 [2] 16 6f [2] 1a 65 [2] 0d 6e [2] 16 20 [2] 2b }

  condition:
    any of them
}