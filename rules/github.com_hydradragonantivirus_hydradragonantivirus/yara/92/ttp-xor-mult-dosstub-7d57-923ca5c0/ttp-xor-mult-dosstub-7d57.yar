rule TTP_XOR_MULT_DOSStub_7d57 {
  strings:
    $key_7d57 = { 29 3f [2] 5d 27 [2] 1a 25 [2] 5d 34 [2] 13 38 [2] 1f 32 [2] 08 39 [2] 13 77 [2] 2e }

  condition:
    any of them
}