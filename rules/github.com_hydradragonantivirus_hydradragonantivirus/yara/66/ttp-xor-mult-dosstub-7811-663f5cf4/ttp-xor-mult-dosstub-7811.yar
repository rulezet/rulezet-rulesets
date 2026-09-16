rule TTP_XOR_MULT_DOSStub_7811 {
  strings:
    $key_7811 = { 2c 79 [2] 58 61 [2] 1f 63 [2] 58 72 [2] 16 7e [2] 1a 74 [2] 0d 7f [2] 16 31 [2] 2b }

  condition:
    any of them
}