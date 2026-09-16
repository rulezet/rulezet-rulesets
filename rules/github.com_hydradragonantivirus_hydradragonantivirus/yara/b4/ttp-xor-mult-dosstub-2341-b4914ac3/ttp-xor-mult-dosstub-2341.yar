rule TTP_XOR_MULT_DOSStub_2341 {
  strings:
    $key_2341 = { 77 29 [2] 03 31 [2] 44 33 [2] 03 22 [2] 4d 2e [2] 41 24 [2] 56 2f [2] 4d 61 [2] 70 }

  condition:
    any of them
}