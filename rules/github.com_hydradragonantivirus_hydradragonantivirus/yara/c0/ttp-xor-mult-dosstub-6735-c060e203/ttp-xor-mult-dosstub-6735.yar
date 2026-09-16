rule TTP_XOR_MULT_DOSStub_6735 {
  strings:
    $key_6735 = { 33 5d [2] 47 45 [2] 00 47 [2] 47 56 [2] 09 5a [2] 05 50 [2] 12 5b [2] 09 15 [2] 34 }

  condition:
    any of them
}