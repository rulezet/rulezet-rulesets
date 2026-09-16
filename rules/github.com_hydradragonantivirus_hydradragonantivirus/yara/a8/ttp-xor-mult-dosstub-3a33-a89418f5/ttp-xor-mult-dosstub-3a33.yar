rule TTP_XOR_MULT_DOSStub_3a33 {
  strings:
    $key_3a33 = { 6e 5b [2] 1a 43 [2] 5d 41 [2] 1a 50 [2] 54 5c [2] 58 56 [2] 4f 5d [2] 54 13 [2] 69 }

  condition:
    any of them
}