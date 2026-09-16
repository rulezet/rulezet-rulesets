rule TTP_XOR_MULT_DOSStub_2319 {
  strings:
    $key_2319 = { 77 71 [2] 03 69 [2] 44 6b [2] 03 7a [2] 4d 76 [2] 41 7c [2] 56 77 [2] 4d 39 [2] 70 }

  condition:
    any of them
}