rule TTP_XOR_MULT_DOSStub_1338 {
  strings:
    $key_1338 = { 47 50 [2] 33 48 [2] 74 4a [2] 33 5b [2] 7d 57 [2] 71 5d [2] 66 56 [2] 7d 18 [2] 40 }

  condition:
    any of them
}