rule TTP_XOR_MULT_DOSStub_7a59 {
  strings:
    $key_7a59 = { 2e 31 [2] 5a 29 [2] 1d 2b [2] 5a 3a [2] 14 36 [2] 18 3c [2] 0f 37 [2] 14 79 [2] 29 }

  condition:
    any of them
}