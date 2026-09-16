rule TTP_XOR_MULT_DOSStub_0319 {
  strings:
    $key_0319 = { 57 71 [2] 23 69 [2] 64 6b [2] 23 7a [2] 6d 76 [2] 61 7c [2] 76 77 [2] 6d 39 [2] 50 }

  condition:
    any of them
}