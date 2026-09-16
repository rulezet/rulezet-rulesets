rule TTP_XOR_MULT_DOSStub_4166 {
  strings:
    $key_4166 = { 15 0e [2] 61 16 [2] 26 14 [2] 61 05 [2] 2f 09 [2] 23 03 [2] 34 08 [2] 2f 46 [2] 12 }

  condition:
    any of them
}