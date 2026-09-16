rule TTP_XOR_MULT_DOSStub_2304 {
  strings:
    $key_2304 = { 77 6c [2] 03 74 [2] 44 76 [2] 03 67 [2] 4d 6b [2] 41 61 [2] 56 6a [2] 4d 24 [2] 70 }

  condition:
    any of them
}