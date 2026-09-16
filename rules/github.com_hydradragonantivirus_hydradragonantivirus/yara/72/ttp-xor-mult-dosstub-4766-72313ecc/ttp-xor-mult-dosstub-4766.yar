rule TTP_XOR_MULT_DOSStub_4766 {
  strings:
    $key_4766 = { 13 0e [2] 67 16 [2] 20 14 [2] 67 05 [2] 29 09 [2] 25 03 [2] 32 08 [2] 29 46 [2] 14 }

  condition:
    any of them
}