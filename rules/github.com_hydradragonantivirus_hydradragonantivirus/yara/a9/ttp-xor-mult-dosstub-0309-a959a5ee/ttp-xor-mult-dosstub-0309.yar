rule TTP_XOR_MULT_DOSStub_0309 {
  strings:
    $key_0309 = { 57 61 [2] 23 79 [2] 64 7b [2] 23 6a [2] 6d 66 [2] 61 6c [2] 76 67 [2] 6d 29 [2] 50 }

  condition:
    any of them
}