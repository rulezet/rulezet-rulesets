rule TTP_XOR_MULT_DOSStub_2323 {
  strings:
    $key_2323 = { 77 4b [2] 03 53 [2] 44 51 [2] 03 40 [2] 4d 4c [2] 41 46 [2] 56 4d [2] 4d 03 [2] 70 }

  condition:
    any of them
}