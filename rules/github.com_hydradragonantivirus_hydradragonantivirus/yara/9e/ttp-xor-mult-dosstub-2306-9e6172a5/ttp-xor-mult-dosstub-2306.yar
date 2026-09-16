rule TTP_XOR_MULT_DOSStub_2306 {
  strings:
    $key_2306 = { 77 6e [2] 03 76 [2] 44 74 [2] 03 65 [2] 4d 69 [2] 41 63 [2] 56 68 [2] 4d 26 [2] 70 }

  condition:
    any of them
}