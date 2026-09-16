rule TTP_XOR_MULT_DOSStub_5607 {
  strings:
    $key_5607 = { 02 6f [2] 76 77 [2] 31 75 [2] 76 64 [2] 38 68 [2] 34 62 [2] 23 69 [2] 38 27 [2] 05 }

  condition:
    any of them
}