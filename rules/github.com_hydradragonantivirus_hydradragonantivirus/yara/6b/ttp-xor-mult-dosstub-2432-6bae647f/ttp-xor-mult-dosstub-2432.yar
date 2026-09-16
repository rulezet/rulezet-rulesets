rule TTP_XOR_MULT_DOSStub_2432 {
  strings:
    $key_2432 = { 70 5a [2] 04 42 [2] 43 40 [2] 04 51 [2] 4a 5d [2] 46 57 [2] 51 5c [2] 4a 12 [2] 77 }

  condition:
    any of them
}