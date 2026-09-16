rule TTP_XOR_MULT_DOSStub_2360 {
  strings:
    $key_2360 = { 77 08 [2] 03 10 [2] 44 12 [2] 03 03 [2] 4d 0f [2] 41 05 [2] 56 0e [2] 4d 40 [2] 70 }

  condition:
    any of them
}