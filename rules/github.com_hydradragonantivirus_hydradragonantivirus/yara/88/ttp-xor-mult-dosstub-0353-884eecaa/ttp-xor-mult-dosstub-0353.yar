rule TTP_XOR_MULT_DOSStub_0353 {
  strings:
    $key_0353 = { 57 3b [2] 23 23 [2] 64 21 [2] 23 30 [2] 6d 3c [2] 61 36 [2] 76 3d [2] 6d 73 [2] 50 }

  condition:
    any of them
}