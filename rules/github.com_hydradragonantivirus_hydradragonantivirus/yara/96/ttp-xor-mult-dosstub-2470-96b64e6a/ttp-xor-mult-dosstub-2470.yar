rule TTP_XOR_MULT_DOSStub_2470 {
  strings:
    $key_2470 = { 70 18 [2] 04 00 [2] 43 02 [2] 04 13 [2] 4a 1f [2] 46 15 [2] 51 1e [2] 4a 50 [2] 77 }

  condition:
    any of them
}