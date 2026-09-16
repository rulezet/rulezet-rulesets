rule TTP_XOR_MULT_DOSStub_1a33 {
  strings:
    $key_1a33 = { 4e 5b [2] 3a 43 [2] 7d 41 [2] 3a 50 [2] 74 5c [2] 78 56 [2] 6f 5d [2] 74 13 [2] 49 }

  condition:
    any of them
}