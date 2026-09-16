rule TTP_XOR_MULT_DOSStub_5d33 {
  strings:
    $key_5d33 = { 09 5b [2] 7d 43 [2] 3a 41 [2] 7d 50 [2] 33 5c [2] 3f 56 [2] 28 5d [2] 33 13 [2] 0e }

  condition:
    any of them
}