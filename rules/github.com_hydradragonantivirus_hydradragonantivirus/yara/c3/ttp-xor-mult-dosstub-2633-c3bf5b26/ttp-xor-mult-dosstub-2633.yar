rule TTP_XOR_MULT_DOSStub_2633 {
  strings:
    $key_2633 = { 72 5b [2] 06 43 [2] 41 41 [2] 06 50 [2] 48 5c [2] 44 56 [2] 53 5d [2] 48 13 [2] 75 }

  condition:
    any of them
}