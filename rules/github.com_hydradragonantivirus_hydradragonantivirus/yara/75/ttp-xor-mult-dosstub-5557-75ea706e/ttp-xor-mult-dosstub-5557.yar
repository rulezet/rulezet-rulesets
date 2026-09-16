rule TTP_XOR_MULT_DOSStub_5557 {
  strings:
    $key_5557 = { 01 3f [2] 75 27 [2] 32 25 [2] 75 34 [2] 3b 38 [2] 37 32 [2] 20 39 [2] 3b 77 [2] 06 }

  condition:
    any of them
}