rule TTP_XOR_MULT_DOSStub_2479 {
  strings:
    $key_2479 = { 70 11 [2] 04 09 [2] 43 0b [2] 04 1a [2] 4a 16 [2] 46 1c [2] 51 17 [2] 4a 59 [2] 77 }

  condition:
    any of them
}