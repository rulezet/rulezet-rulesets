rule TTP_XOR_MULT_DOSStub_3a66 {
  strings:
    $key_3a66 = { 6e 0e [2] 1a 16 [2] 5d 14 [2] 1a 05 [2] 54 09 [2] 58 03 [2] 4f 08 [2] 54 46 [2] 69 }

  condition:
    any of them
}