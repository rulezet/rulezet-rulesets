rule TTP_XOR_MULT_DOSStub_7817 {
  strings:
    $key_7817 = { 2c 7f [2] 58 67 [2] 1f 65 [2] 58 74 [2] 16 78 [2] 1a 72 [2] 0d 79 [2] 16 37 [2] 2b }

  condition:
    any of them
}