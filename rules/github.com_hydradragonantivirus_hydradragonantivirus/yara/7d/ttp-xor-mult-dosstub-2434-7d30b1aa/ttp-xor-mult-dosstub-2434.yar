rule TTP_XOR_MULT_DOSStub_2434 {
  strings:
    $key_2434 = { 70 5c [2] 04 44 [2] 43 46 [2] 04 57 [2] 4a 5b [2] 46 51 [2] 51 5a [2] 4a 14 [2] 77 }

  condition:
    any of them
}