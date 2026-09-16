rule TTP_XOR_MULT_DOSStub_2324 {
  strings:
    $key_2324 = { 77 4c [2] 03 54 [2] 44 56 [2] 03 47 [2] 4d 4b [2] 41 41 [2] 56 4a [2] 4d 04 [2] 70 }

  condition:
    any of them
}