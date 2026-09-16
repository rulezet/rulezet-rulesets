rule TTP_XOR_MULT_DOSStub_5238 {
  strings:
    $key_5238 = { 06 50 [2] 72 48 [2] 35 4a [2] 72 5b [2] 3c 57 [2] 30 5d [2] 27 56 [2] 3c 18 [2] 01 }

  condition:
    any of them
}