rule TTP_XOR_MULT_DOSStub_4b77 {
  strings:
    $key_4b77 = { 1f 1f [2] 6b 07 [2] 2c 05 [2] 6b 14 [2] 25 18 [2] 29 12 [2] 3e 19 [2] 25 57 [2] 18 }

  condition:
    any of them
}