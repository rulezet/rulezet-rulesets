rule TTP_XOR_MULT_DOSStub_7801 {
  strings:
    $key_7801 = { 2c 69 [2] 58 71 [2] 1f 73 [2] 58 62 [2] 16 6e [2] 1a 64 [2] 0d 6f [2] 16 21 [2] 2b }

  condition:
    any of them
}