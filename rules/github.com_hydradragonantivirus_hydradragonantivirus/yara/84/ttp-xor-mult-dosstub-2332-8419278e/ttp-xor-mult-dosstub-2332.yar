rule TTP_XOR_MULT_DOSStub_2332 {
  strings:
    $key_2332 = { 77 5a [2] 03 42 [2] 44 40 [2] 03 51 [2] 4d 5d [2] 41 57 [2] 56 5c [2] 4d 12 [2] 70 }

  condition:
    any of them
}