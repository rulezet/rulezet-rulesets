rule TTP_XOR_MULT_DOSStub_7c66 {
  strings:
    $key_7c66 = { 28 0e [2] 5c 16 [2] 1b 14 [2] 5c 05 [2] 12 09 [2] 1e 03 [2] 09 08 [2] 12 46 [2] 2f }

  condition:
    any of them
}