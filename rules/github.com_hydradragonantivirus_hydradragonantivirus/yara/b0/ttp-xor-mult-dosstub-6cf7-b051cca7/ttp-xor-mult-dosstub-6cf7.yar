rule TTP_XOR_MULT_DOSStub_6cf7 {
  strings:
    $key_6cf7 = { 38 9f [2] 4c 87 [2] 0b 85 [2] 4c 94 [2] 02 98 [2] 0e 92 [2] 19 99 [2] 02 d7 [2] 3f }

  condition:
    any of them
}