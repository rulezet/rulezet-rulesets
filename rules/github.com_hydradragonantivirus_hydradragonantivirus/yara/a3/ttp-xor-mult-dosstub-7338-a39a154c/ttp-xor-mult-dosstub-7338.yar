rule TTP_XOR_MULT_DOSStub_7338 {
  strings:
    $key_7338 = { 27 50 [2] 53 48 [2] 14 4a [2] 53 5b [2] 1d 57 [2] 11 5d [2] 06 56 [2] 1d 18 [2] 20 }

  condition:
    any of them
}