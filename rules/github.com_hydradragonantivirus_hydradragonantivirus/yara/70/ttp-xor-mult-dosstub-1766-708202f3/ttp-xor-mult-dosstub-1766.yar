rule TTP_XOR_MULT_DOSStub_1766 {
  strings:
    $key_1766 = { 43 0e [2] 37 16 [2] 70 14 [2] 37 05 [2] 79 09 [2] 75 03 [2] 62 08 [2] 79 46 [2] 44 }

  condition:
    any of them
}