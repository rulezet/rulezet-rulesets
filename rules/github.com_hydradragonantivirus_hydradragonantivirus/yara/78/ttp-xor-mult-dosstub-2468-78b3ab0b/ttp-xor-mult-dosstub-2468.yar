rule TTP_XOR_MULT_DOSStub_2468 {
  strings:
    $key_2468 = { 70 00 [2] 04 18 [2] 43 1a [2] 04 0b [2] 4a 07 [2] 46 0d [2] 51 06 [2] 4a 48 [2] 77 }

  condition:
    any of them
}