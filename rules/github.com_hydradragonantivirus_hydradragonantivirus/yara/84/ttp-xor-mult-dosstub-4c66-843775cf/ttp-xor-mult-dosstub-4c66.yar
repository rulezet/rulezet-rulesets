rule TTP_XOR_MULT_DOSStub_4c66 {
  strings:
    $key_4c66 = { 18 0e [2] 6c 16 [2] 2b 14 [2] 6c 05 [2] 22 09 [2] 2e 03 [2] 39 08 [2] 22 46 [2] 1f }

  condition:
    any of them
}