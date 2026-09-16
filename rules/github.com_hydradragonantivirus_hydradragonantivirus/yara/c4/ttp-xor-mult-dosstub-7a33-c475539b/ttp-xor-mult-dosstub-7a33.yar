rule TTP_XOR_MULT_DOSStub_7a33 {
  strings:
    $key_7a33 = { 2e 5b [2] 5a 43 [2] 1d 41 [2] 5a 50 [2] 14 5c [2] 18 56 [2] 0f 5d [2] 14 13 [2] 29 }

  condition:
    any of them
}