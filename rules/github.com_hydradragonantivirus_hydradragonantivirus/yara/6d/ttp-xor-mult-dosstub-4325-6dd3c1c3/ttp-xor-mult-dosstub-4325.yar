rule TTP_XOR_MULT_DOSStub_4325 {
  strings:
    $key_4325 = { 17 4d [2] 63 55 [2] 24 57 [2] 63 46 [2] 2d 4a [2] 21 40 [2] 36 4b [2] 2d 05 [2] 10 }

  condition:
    any of them
}