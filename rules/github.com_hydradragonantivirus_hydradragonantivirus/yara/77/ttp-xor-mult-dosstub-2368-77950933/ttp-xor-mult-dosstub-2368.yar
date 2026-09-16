rule TTP_XOR_MULT_DOSStub_2368 {
  strings:
    $key_2368 = { 77 00 [2] 03 18 [2] 44 1a [2] 03 0b [2] 4d 07 [2] 41 0d [2] 56 06 [2] 4d 48 [2] 70 }

  condition:
    any of them
}