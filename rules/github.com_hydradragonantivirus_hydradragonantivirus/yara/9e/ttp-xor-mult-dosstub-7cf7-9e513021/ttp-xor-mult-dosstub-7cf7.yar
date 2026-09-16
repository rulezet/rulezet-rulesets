rule TTP_XOR_MULT_DOSStub_7cf7 {
  strings:
    $key_7cf7 = { 28 9f [2] 5c 87 [2] 1b 85 [2] 5c 94 [2] 12 98 [2] 1e 92 [2] 09 99 [2] 12 d7 [2] 2f }

  condition:
    any of them
}