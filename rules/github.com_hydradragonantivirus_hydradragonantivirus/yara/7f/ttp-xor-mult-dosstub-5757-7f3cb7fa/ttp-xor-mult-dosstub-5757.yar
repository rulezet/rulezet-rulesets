rule TTP_XOR_MULT_DOSStub_5757 {
  strings:
    $key_5757 = { 03 3f [2] 77 27 [2] 30 25 [2] 77 34 [2] 39 38 [2] 35 32 [2] 22 39 [2] 39 77 [2] 04 }

  condition:
    any of them
}