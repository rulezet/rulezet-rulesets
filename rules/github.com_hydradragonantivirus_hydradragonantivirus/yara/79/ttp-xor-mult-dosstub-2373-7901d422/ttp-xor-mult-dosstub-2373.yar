rule TTP_XOR_MULT_DOSStub_2373 {
  strings:
    $key_2373 = { 77 1b [2] 03 03 [2] 44 01 [2] 03 10 [2] 4d 1c [2] 41 16 [2] 56 1d [2] 4d 53 [2] 70 }

  condition:
    any of them
}