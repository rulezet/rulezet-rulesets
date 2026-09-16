rule TTP_XOR_MULT_DOSStub_2475 {
  strings:
    $key_2475 = { 70 1d [2] 04 05 [2] 43 07 [2] 04 16 [2] 4a 1a [2] 46 10 [2] 51 1b [2] 4a 55 [2] 77 }

  condition:
    any of them
}