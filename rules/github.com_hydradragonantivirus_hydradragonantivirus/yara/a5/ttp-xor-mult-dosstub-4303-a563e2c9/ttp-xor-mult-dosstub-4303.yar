rule TTP_XOR_MULT_DOSStub_4303 {
  strings:
    $key_4303 = { 17 6b [2] 63 73 [2] 24 71 [2] 63 60 [2] 2d 6c [2] 21 66 [2] 36 6d [2] 2d 23 [2] 10 }

  condition:
    any of them
}