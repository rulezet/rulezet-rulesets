rule TTP_XOR_MULT_DOSStub_5666 {
  strings:
    $key_5666 = { 02 0e [2] 76 16 [2] 31 14 [2] 76 05 [2] 38 09 [2] 34 03 [2] 23 08 [2] 38 46 [2] 05 }

  condition:
    any of them
}