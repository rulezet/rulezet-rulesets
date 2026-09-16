rule TTP_XOR_MULT_DOSStub_1757 {
  strings:
    $key_1757 = { 43 3f [2] 37 27 [2] 70 25 [2] 37 34 [2] 79 38 [2] 75 32 [2] 62 39 [2] 79 77 [2] 44 }

  condition:
    any of them
}