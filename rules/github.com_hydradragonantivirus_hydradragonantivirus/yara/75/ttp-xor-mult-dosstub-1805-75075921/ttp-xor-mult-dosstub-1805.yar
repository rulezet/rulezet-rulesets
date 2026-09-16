rule TTP_XOR_MULT_DOSStub_1805 {
  strings:
    $key_1805 = { 4c 6d [2] 38 75 [2] 7f 77 [2] 38 66 [2] 76 6a [2] 7a 60 [2] 6d 6b [2] 76 25 [2] 4b }

  condition:
    any of them
}