rule TTP_XOR_MULT_DOSStub_4339 {
  strings:
    $key_4339 = { 17 51 [2] 63 49 [2] 24 4b [2] 63 5a [2] 2d 56 [2] 21 5c [2] 36 57 [2] 2d 19 [2] 10 }

  condition:
    any of them
}