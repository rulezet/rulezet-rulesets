rule TTP_XOR_MULT_DOSStub_4333 {
  strings:
    $key_4333 = { 17 5b [2] 63 43 [2] 24 41 [2] 63 50 [2] 2d 5c [2] 21 56 [2] 36 5d [2] 2d 13 [2] 10 }

  condition:
    any of them
}