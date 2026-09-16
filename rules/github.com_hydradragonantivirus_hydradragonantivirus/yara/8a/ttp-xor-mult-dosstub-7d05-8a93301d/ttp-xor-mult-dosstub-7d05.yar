rule TTP_XOR_MULT_DOSStub_7d05 {
  strings:
    $key_7d05 = { 29 6d [2] 5d 75 [2] 1a 77 [2] 5d 66 [2] 13 6a [2] 1f 60 [2] 08 6b [2] 13 25 [2] 2e }

  condition:
    any of them
}