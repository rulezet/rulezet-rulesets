rule TTP_XOR_MULT_DOSStub_7b77 {
  strings:
    $key_7b77 = { 2f 1f [2] 5b 07 [2] 1c 05 [2] 5b 14 [2] 15 18 [2] 19 12 [2] 0e 19 [2] 15 57 [2] 28 }

  condition:
    any of them
}