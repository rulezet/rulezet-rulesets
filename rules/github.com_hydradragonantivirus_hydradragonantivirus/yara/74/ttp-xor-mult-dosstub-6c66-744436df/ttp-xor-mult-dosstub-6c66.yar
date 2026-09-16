rule TTP_XOR_MULT_DOSStub_6c66 {
  strings:
    $key_6c66 = { 38 0e [2] 4c 16 [2] 0b 14 [2] 4c 05 [2] 02 09 [2] 0e 03 [2] 19 08 [2] 02 46 [2] 3f }

  condition:
    any of them
}