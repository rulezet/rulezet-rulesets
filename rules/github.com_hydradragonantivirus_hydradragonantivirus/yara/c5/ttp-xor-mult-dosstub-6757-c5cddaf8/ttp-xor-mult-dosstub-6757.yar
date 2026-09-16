rule TTP_XOR_MULT_DOSStub_6757 {
  strings:
    $key_6757 = { 33 3f [2] 47 27 [2] 00 25 [2] 47 34 [2] 09 38 [2] 05 32 [2] 12 39 [2] 09 77 [2] 34 }

  condition:
    any of them
}