rule TTP_XOR_MULT_DOSStub_1438 {
  strings:
    $key_1438 = { 40 50 [2] 34 48 [2] 73 4a [2] 34 5b [2] 7a 57 [2] 76 5d [2] 61 56 [2] 7a 18 [2] 47 }

  condition:
    any of them
}