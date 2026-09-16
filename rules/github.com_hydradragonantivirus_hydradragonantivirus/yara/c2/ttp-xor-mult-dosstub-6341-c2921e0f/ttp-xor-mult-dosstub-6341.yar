rule TTP_XOR_MULT_DOSStub_6341 {
  strings:
    $key_6341 = { 37 29 [2] 43 31 [2] 04 33 [2] 43 22 [2] 0d 2e [2] 01 24 [2] 16 2f [2] 0d 61 [2] 30 }

  condition:
    any of them
}