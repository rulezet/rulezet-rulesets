rule TTP_XOR_MULT_DOSStub_1605 {
  strings:
    $key_1605 = { 42 6d [2] 36 75 [2] 71 77 [2] 36 66 [2] 78 6a [2] 74 60 [2] 63 6b [2] 78 25 [2] 45 }

  condition:
    any of them
}