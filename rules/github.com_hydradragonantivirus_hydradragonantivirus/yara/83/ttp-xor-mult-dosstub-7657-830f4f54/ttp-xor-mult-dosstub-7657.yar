rule TTP_XOR_MULT_DOSStub_7657 {
  strings:
    $key_7657 = { 22 3f [2] 56 27 [2] 11 25 [2] 56 34 [2] 18 38 [2] 14 32 [2] 03 39 [2] 18 77 [2] 25 }

  condition:
    any of them
}