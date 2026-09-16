rule TTP_XOR_MULT_DOSStub_2371 {
  strings:
    $key_2371 = { 77 19 [2] 03 01 [2] 44 03 [2] 03 12 [2] 4d 1e [2] 41 14 [2] 56 1f [2] 4d 51 [2] 70 }

  condition:
    any of them
}