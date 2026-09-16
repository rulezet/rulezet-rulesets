rule TTP_XOR_MULT_DOSStub_2472 {
  strings:
    $key_2472 = { 70 1a [2] 04 02 [2] 43 00 [2] 04 11 [2] 4a 1d [2] 46 17 [2] 51 1c [2] 4a 52 [2] 77 }

  condition:
    any of them
}