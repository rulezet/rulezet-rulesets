rule TTP_XOR_MULT_DOSStub_78e4 {
  strings:
    $key_78e4 = { 2c 8c [2] 58 94 [2] 1f 96 [2] 58 87 [2] 16 8b [2] 1a 81 [2] 0d 8a [2] 16 c4 [2] 2b }

  condition:
    any of them
}