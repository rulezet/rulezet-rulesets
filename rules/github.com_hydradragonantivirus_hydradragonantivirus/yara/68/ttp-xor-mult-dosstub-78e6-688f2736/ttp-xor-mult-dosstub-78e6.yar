rule TTP_XOR_MULT_DOSStub_78e6 {
  strings:
    $key_78e6 = { 2c 8e [2] 58 96 [2] 1f 94 [2] 58 85 [2] 16 89 [2] 1a 83 [2] 0d 88 [2] 16 c6 [2] 2b }

  condition:
    any of them
}