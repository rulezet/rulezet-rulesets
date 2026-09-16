rule TTP_XOR_MULT_DOSStub_6357 {
  strings:
    $key_6357 = { 37 3f [2] 43 27 [2] 04 25 [2] 43 34 [2] 0d 38 [2] 01 32 [2] 16 39 [2] 0d 77 [2] 30 }

  condition:
    any of them
}