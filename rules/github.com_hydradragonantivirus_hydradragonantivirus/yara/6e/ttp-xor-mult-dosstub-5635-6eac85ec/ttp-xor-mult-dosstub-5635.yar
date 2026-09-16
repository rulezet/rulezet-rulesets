rule TTP_XOR_MULT_DOSStub_5635 {
  strings:
    $key_5635 = { 02 5d [2] 76 45 [2] 31 47 [2] 76 56 [2] 38 5a [2] 34 50 [2] 23 5b [2] 38 15 [2] 05 }

  condition:
    any of them
}