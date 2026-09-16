rule TTP_XOR_MULT_DOSStub_7635 {
  strings:
    $key_7635 = { 22 5d [2] 56 45 [2] 11 47 [2] 56 56 [2] 18 5a [2] 14 50 [2] 03 5b [2] 18 15 [2] 25 }

  condition:
    any of them
}