rule TTP_XOR_MULT_DOSStub_3357 {
  strings:
    $key_3357 = { 67 3f [2] 13 27 [2] 54 25 [2] 13 34 [2] 5d 38 [2] 51 32 [2] 46 39 [2] 5d 77 [2] 60 }

  condition:
    any of them
}