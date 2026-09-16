rule TTP_XOR_MULT_DOSStub_7366 {
  strings:
    $key_7366 = { 27 0e [2] 53 16 [2] 14 14 [2] 53 05 [2] 1d 09 [2] 11 03 [2] 06 08 [2] 1d 46 [2] 20 }

  condition:
    any of them
}