rule TTP_XOR_MULT_DOSStub_7a77 {
  strings:
    $key_7a77 = { 2e 1f [2] 5a 07 [2] 1d 05 [2] 5a 14 [2] 14 18 [2] 18 12 [2] 0f 19 [2] 14 57 [2] 29 }

  condition:
    any of them
}