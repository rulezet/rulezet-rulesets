rule TTP_XOR_MULT_DOSStub_7a25 {
  strings:
    $key_7a25 = { 2e 4d [2] 5a 55 [2] 1d 57 [2] 5a 46 [2] 14 4a [2] 18 40 [2] 0f 4b [2] 14 05 [2] 29 }

  condition:
    any of them
}