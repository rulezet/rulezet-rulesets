rule TTP_XOR_MULT_DOSStub_3b77 {
  strings:
    $key_3b77 = { 6f 1f [2] 1b 07 [2] 5c 05 [2] 1b 14 [2] 55 18 [2] 59 12 [2] 4e 19 [2] 55 57 [2] 68 }

  condition:
    any of them
}