rule TTP_XOR_MULT_DOSStub_6356 {
  strings:
    $key_6356 = { 37 3e [2] 43 26 [2] 04 24 [2] 43 35 [2] 0d 39 [2] 01 33 [2] 16 38 [2] 0d 76 [2] 30 }

  condition:
    any of them
}