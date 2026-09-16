rule TTP_XOR_MULT_DOSStub_2339 {
  strings:
    $key_2339 = { 77 51 [2] 03 49 [2] 44 4b [2] 03 5a [2] 4d 56 [2] 41 5c [2] 56 57 [2] 4d 19 [2] 70 }

  condition:
    any of them
}