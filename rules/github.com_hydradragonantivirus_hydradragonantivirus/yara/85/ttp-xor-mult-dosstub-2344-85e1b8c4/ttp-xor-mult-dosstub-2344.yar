rule TTP_XOR_MULT_DOSStub_2344 {
  strings:
    $key_2344 = { 77 2c [2] 03 34 [2] 44 36 [2] 03 27 [2] 4d 2b [2] 41 21 [2] 56 2a [2] 4d 64 [2] 70 }

  condition:
    any of them
}