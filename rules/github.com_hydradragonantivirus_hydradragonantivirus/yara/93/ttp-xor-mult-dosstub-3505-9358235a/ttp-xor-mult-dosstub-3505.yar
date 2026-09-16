rule TTP_XOR_MULT_DOSStub_3505 {
  strings:
    $key_3505 = { 61 6d [2] 15 75 [2] 52 77 [2] 15 66 [2] 5b 6a [2] 57 60 [2] 40 6b [2] 5b 25 [2] 66 }

  condition:
    any of them
}