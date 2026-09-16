rule TTP_XOR_MULT_DOSStub_1719 {
  strings:
    $key_1719 = { 43 71 [2] 37 69 [2] 70 6b [2] 37 7a [2] 79 76 [2] 75 7c [2] 62 77 [2] 79 39 [2] 44 }

  condition:
    any of them
}