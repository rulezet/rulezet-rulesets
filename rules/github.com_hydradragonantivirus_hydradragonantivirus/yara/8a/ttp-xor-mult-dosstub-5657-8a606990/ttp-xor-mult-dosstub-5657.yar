rule TTP_XOR_MULT_DOSStub_5657 {
  strings:
    $key_5657 = { 02 3f [2] 76 27 [2] 31 25 [2] 76 34 [2] 38 38 [2] 34 32 [2] 23 39 [2] 38 77 [2] 05 }

  condition:
    any of them
}