rule TTP_XOR_MULT_DOSStub_2325 {
  strings:
    $key_2325 = { 77 4d [2] 03 55 [2] 44 57 [2] 03 46 [2] 4d 4a [2] 41 40 [2] 56 4b [2] 4d 05 [2] 70 }

  condition:
    any of them
}