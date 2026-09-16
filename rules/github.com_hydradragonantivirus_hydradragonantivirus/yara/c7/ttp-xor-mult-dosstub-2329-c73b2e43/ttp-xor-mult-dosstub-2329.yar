rule TTP_XOR_MULT_DOSStub_2329 {
  strings:
    $key_2329 = { 77 41 [2] 03 59 [2] 44 5b [2] 03 4a [2] 4d 46 [2] 41 4c [2] 56 47 [2] 4d 09 [2] 70 }

  condition:
    any of them
}