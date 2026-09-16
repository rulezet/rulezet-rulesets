rule TTP_XOR_MULT_DOSStub_7333 {
  strings:
    $key_7333 = { 27 5b [2] 53 43 [2] 14 41 [2] 53 50 [2] 1d 5c [2] 11 56 [2] 06 5d [2] 1d 13 [2] 20 }

  condition:
    any of them
}