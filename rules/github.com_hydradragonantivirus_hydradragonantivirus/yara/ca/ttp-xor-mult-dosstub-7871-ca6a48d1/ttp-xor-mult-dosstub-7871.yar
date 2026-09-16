rule TTP_XOR_MULT_DOSStub_7871 {
  strings:
    $key_7871 = { 2c 19 [2] 58 01 [2] 1f 03 [2] 58 12 [2] 16 1e [2] 1a 14 [2] 0d 1f [2] 16 51 [2] 2b }

  condition:
    any of them
}