rule TTP_XOR_MULT_DOSStub_7339 {
  strings:
    $key_7339 = { 27 51 [2] 53 49 [2] 14 4b [2] 53 5a [2] 1d 56 [2] 11 5c [2] 06 57 [2] 1d 19 [2] 20 }

  condition:
    any of them
}