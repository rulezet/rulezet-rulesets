rule TTP_XOR_MULT_DOSStub_78f7 {
  strings:
    $key_78f7 = { 2c 9f [2] 58 87 [2] 1f 85 [2] 58 94 [2] 16 98 [2] 1a 92 [2] 0d 99 [2] 16 d7 [2] 2b }

  condition:
    any of them
}