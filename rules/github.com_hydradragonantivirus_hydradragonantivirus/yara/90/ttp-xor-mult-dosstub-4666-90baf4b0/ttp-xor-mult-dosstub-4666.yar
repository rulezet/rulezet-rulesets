rule TTP_XOR_MULT_DOSStub_4666 {
  strings:
    $key_4666 = { 12 0e [2] 66 16 [2] 21 14 [2] 66 05 [2] 28 09 [2] 24 03 [2] 33 08 [2] 28 46 [2] 15 }

  condition:
    any of them
}