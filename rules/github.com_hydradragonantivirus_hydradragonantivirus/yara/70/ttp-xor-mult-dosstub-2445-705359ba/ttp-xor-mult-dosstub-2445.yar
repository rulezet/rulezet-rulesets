rule TTP_XOR_MULT_DOSStub_2445 {
  strings:
    $key_2445 = { 70 2d [2] 04 35 [2] 43 37 [2] 04 26 [2] 4a 2a [2] 46 20 [2] 51 2b [2] 4a 65 [2] 77 }

  condition:
    any of them
}