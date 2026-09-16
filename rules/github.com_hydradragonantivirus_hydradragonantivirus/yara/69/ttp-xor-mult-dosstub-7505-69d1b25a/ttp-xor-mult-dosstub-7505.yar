rule TTP_XOR_MULT_DOSStub_7505 {
  strings:
    $key_7505 = { 21 6d [2] 55 75 [2] 12 77 [2] 55 66 [2] 1b 6a [2] 17 60 [2] 00 6b [2] 1b 25 [2] 26 }

  condition:
    any of them
}