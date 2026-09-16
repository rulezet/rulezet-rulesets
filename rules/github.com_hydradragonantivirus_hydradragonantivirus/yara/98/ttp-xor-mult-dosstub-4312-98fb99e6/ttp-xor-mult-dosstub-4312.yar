rule TTP_XOR_MULT_DOSStub_4312 {
  strings:
    $key_4312 = { 17 7a [2] 63 62 [2] 24 60 [2] 63 71 [2] 2d 7d [2] 21 77 [2] 36 7c [2] 2d 32 [2] 10 }

  condition:
    any of them
}