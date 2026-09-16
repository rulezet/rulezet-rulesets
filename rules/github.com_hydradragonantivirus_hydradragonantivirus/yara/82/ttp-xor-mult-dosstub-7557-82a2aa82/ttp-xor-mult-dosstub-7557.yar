rule TTP_XOR_MULT_DOSStub_7557 {
  strings:
    $key_7557 = { 21 3f [2] 55 27 [2] 12 25 [2] 55 34 [2] 1b 38 [2] 17 32 [2] 00 39 [2] 1b 77 [2] 26 }

  condition:
    any of them
}