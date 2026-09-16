rule TTP_XOR_MULT_DOSStub_5b77 {
  strings:
    $key_5b77 = { 0f 1f [2] 7b 07 [2] 3c 05 [2] 7b 14 [2] 35 18 [2] 39 12 [2] 2e 19 [2] 35 57 [2] 08 }

  condition:
    any of them
}