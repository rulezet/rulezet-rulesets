rule TTP_XOR_MULT_DOSStub_7607 {
  strings:
    $key_7607 = { 22 6f [2] 56 77 [2] 11 75 [2] 56 64 [2] 18 68 [2] 14 62 [2] 03 69 [2] 18 27 [2] 25 }

  condition:
    any of them
}