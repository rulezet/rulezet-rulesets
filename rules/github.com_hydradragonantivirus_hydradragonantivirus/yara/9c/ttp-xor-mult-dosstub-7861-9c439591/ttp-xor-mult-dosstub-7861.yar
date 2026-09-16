rule TTP_XOR_MULT_DOSStub_7861 {
  strings:
    $key_7861 = { 2c 09 [2] 58 11 [2] 1f 13 [2] 58 02 [2] 16 0e [2] 1a 04 [2] 0d 0f [2] 16 41 [2] 2b }

  condition:
    any of them
}