rule TTP_XOR_MULT_DOSStub_1507 {
  strings:
    $key_1507 = { 41 6f [2] 35 77 [2] 72 75 [2] 35 64 [2] 7b 68 [2] 77 62 [2] 60 69 [2] 7b 27 [2] 46 }

  condition:
    any of them
}