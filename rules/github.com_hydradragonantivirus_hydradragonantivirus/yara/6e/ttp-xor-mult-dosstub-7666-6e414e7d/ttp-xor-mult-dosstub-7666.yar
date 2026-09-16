rule TTP_XOR_MULT_DOSStub_7666 {
  strings:
    $key_7666 = { 22 0e [2] 56 16 [2] 11 14 [2] 56 05 [2] 18 09 [2] 14 03 [2] 03 08 [2] 18 46 [2] 25 }

  condition:
    any of them
}