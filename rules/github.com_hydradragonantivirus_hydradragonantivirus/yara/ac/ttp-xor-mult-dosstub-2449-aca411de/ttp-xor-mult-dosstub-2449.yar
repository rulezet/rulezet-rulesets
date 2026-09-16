rule TTP_XOR_MULT_DOSStub_2449 {
  strings:
    $key_2449 = { 70 21 [2] 04 39 [2] 43 3b [2] 04 2a [2] 4a 26 [2] 46 2c [2] 51 27 [2] 4a 69 [2] 77 }

  condition:
    any of them
}