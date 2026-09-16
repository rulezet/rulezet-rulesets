rule TTP_XOR_MULT_DOSStub_4a25 {
  strings:
    $key_4a25 = { 1e 4d [2] 6a 55 [2] 2d 57 [2] 6a 46 [2] 24 4a [2] 28 40 [2] 3f 4b [2] 24 05 [2] 19 }

  condition:
    any of them
}