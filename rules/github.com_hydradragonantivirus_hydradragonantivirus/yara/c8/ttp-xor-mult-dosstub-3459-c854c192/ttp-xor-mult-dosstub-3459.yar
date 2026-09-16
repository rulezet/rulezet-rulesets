rule TTP_XOR_MULT_DOSStub_3459 {
  strings:
    $key_3459 = { 60 31 [2] 14 29 [2] 53 2b [2] 14 3a [2] 5a 36 [2] 56 3c [2] 41 37 [2] 5a 79 [2] 67 }

  condition:
    any of them
}