rule TTP_XOR_MULT_DOSStub_0366 {
  strings:
    $key_0366 = { 57 0e [2] 23 16 [2] 64 14 [2] 23 05 [2] 6d 09 [2] 61 03 [2] 76 08 [2] 6d 46 [2] 50 }

  condition:
    any of them
}