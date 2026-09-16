rule TTP_XOR_MULT_DOSStub_4324 {
  strings:
    $key_4324 = { 17 4c [2] 63 54 [2] 24 56 [2] 63 47 [2] 2d 4b [2] 21 41 [2] 36 4a [2] 2d 04 [2] 10 }

  condition:
    any of them
}