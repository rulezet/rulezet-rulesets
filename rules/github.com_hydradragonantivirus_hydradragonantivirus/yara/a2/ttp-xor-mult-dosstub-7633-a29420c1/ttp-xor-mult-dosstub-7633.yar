rule TTP_XOR_MULT_DOSStub_7633 {
  strings:
    $key_7633 = { 22 5b [2] 56 43 [2] 11 41 [2] 56 50 [2] 18 5c [2] 14 56 [2] 03 5d [2] 18 13 [2] 25 }

  condition:
    any of them
}