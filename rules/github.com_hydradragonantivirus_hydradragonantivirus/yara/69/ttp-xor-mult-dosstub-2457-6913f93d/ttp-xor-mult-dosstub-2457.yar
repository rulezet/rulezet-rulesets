rule TTP_XOR_MULT_DOSStub_2457 {
  strings:
    $key_2457 = { 70 3f [2] 04 27 [2] 43 25 [2] 04 34 [2] 4a 38 [2] 46 32 [2] 51 39 [2] 4a 77 [2] 77 }

  condition:
    any of them
}