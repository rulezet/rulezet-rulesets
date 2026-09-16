rule TTP_XOR_MULT_DOSStub_4319 {
  strings:
    $key_4319 = { 17 71 [2] 63 69 [2] 24 6b [2] 63 7a [2] 2d 76 [2] 21 7c [2] 36 77 [2] 2d 39 [2] 10 }

  condition:
    any of them
}