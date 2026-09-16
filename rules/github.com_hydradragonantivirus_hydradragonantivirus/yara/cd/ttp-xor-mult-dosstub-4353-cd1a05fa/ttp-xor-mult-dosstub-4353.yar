rule TTP_XOR_MULT_DOSStub_4353 {
  strings:
    $key_4353 = { 17 3b [2] 63 23 [2] 24 21 [2] 63 30 [2] 2d 3c [2] 21 36 [2] 36 3d [2] 2d 73 [2] 10 }

  condition:
    any of them
}