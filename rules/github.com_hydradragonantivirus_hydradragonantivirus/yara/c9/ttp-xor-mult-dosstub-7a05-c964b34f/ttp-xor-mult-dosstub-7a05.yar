rule TTP_XOR_MULT_DOSStub_7a05 {
  strings:
    $key_7a05 = { 2e 6d [2] 5a 75 [2] 1d 77 [2] 5a 66 [2] 14 6a [2] 18 60 [2] 0f 6b [2] 14 25 [2] 29 }

  condition:
    any of them
}