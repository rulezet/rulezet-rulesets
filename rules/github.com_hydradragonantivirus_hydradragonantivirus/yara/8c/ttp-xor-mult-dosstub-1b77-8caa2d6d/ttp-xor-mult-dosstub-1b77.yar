rule TTP_XOR_MULT_DOSStub_1b77 {
  strings:
    $key_1b77 = { 4f 1f [2] 3b 07 [2] 7c 05 [2] 3b 14 [2] 75 18 [2] 79 12 [2] 6e 19 [2] 75 57 [2] 48 }

  condition:
    any of them
}