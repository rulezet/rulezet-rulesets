rule TTP_XOR_MULT_DOSStub_3454 {
  strings:
    $key_3454 = { 60 3c [2] 14 24 [2] 53 26 [2] 14 37 [2] 5a 3b [2] 56 31 [2] 41 3a [2] 5a 74 [2] 67 }

  condition:
    any of them
}