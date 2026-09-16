rule TTP_XOR_MULT_DOSStub_2314 {
  strings:
    $key_2314 = { 77 7c [2] 03 64 [2] 44 66 [2] 03 77 [2] 4d 7b [2] 41 71 [2] 56 7a [2] 4d 34 [2] 70 }

  condition:
    any of them
}