rule TTP_XOR_MULT_DOSStub_1714 {
  strings:
    $key_1714 = { 43 7c [2] 37 64 [2] 70 66 [2] 37 77 [2] 79 7b [2] 75 71 [2] 62 7a [2] 79 34 [2] 44 }

  condition:
    any of them
}