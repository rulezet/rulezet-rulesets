rule TTP_XOR_MULT_DOSStub_2317 {
  strings:
    $key_2317 = { 77 7f [2] 03 67 [2] 44 65 [2] 03 74 [2] 4d 78 [2] 41 72 [2] 56 79 [2] 4d 37 [2] 70 }

  condition:
    any of them
}