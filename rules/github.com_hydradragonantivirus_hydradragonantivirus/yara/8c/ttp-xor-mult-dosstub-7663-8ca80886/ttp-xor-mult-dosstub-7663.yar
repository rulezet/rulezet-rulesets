rule TTP_XOR_MULT_DOSStub_7663 {
  strings:
    $key_7663 = { 22 0b [2] 56 13 [2] 11 11 [2] 56 00 [2] 18 0c [2] 14 06 [2] 03 0d [2] 18 43 [2] 25 }

  condition:
    any of them
}