rule TTP_XOR_MULT_DOSStub_4366 {
  strings:
    $key_4366 = { 17 0e [2] 63 16 [2] 24 14 [2] 63 05 [2] 2d 09 [2] 21 03 [2] 36 08 [2] 2d 46 [2] 10 }

  condition:
    any of them
}