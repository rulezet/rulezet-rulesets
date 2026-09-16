rule TTP_XOR_MULT_DOSStub_7806 {
  strings:
    $key_7806 = { 2c 6e [2] 58 76 [2] 1f 74 [2] 58 65 [2] 16 69 [2] 1a 63 [2] 0d 68 [2] 16 26 [2] 2b }

  condition:
    any of them
}