rule TTP_XOR_MULT_DOSStub_2454 {
  strings:
    $key_2454 = { 70 3c [2] 04 24 [2] 43 26 [2] 04 37 [2] 4a 3b [2] 46 31 [2] 51 3a [2] 4a 74 [2] 77 }

  condition:
    any of them
}