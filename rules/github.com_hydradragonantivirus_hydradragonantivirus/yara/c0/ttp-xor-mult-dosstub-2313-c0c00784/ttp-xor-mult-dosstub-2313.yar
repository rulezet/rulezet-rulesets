rule TTP_XOR_MULT_DOSStub_2313 {
  strings:
    $key_2313 = { 77 7b [2] 03 63 [2] 44 61 [2] 03 70 [2] 4d 7c [2] 41 76 [2] 56 7d [2] 4d 33 [2] 70 }

  condition:
    any of them
}