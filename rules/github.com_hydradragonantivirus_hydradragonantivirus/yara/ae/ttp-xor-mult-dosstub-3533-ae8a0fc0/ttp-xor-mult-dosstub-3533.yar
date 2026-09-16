rule TTP_XOR_MULT_DOSStub_3533 {
  strings:
    $key_3533 = { 61 5b [2] 15 43 [2] 52 41 [2] 15 50 [2] 5b 5c [2] 57 56 [2] 40 5d [2] 5b 13 [2] 66 }

  condition:
    any of them
}