rule TTP_XOR_MULT_DOSStub_2438 {
  strings:
    $key_2438 = { 70 50 [2] 04 48 [2] 43 4a [2] 04 5b [2] 4a 57 [2] 46 5d [2] 51 56 [2] 4a 18 [2] 77 }

  condition:
    any of them
}