rule TTP_XOR_MULT_DOSStub_5266 {
  strings:
    $key_5266 = { 06 0e [2] 72 16 [2] 35 14 [2] 72 05 [2] 3c 09 [2] 30 03 [2] 27 08 [2] 3c 46 [2] 01 }

  condition:
    any of them
}