rule TTP_XOR_MULT_DOSStub_4d33 {
  strings:
    $key_4d33 = { 19 5b [2] 6d 43 [2] 2a 41 [2] 6d 50 [2] 23 5c [2] 2f 56 [2] 38 5d [2] 23 13 [2] 1e }

  condition:
    any of them
}