rule TTP_XOR_MULT_DOSStub_0305 {
  strings:
    $key_0305 = { 57 6d [2] 23 75 [2] 64 77 [2] 23 66 [2] 6d 6a [2] 61 60 [2] 76 6b [2] 6d 25 [2] 50 }

  condition:
    any of them
}