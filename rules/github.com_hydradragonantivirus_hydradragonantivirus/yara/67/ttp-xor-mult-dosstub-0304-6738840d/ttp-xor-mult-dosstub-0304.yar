rule TTP_XOR_MULT_DOSStub_0304 {
  strings:
    $key_0304 = { 57 6c [2] 23 74 [2] 64 76 [2] 23 67 [2] 6d 6b [2] 61 61 [2] 76 6a [2] 6d 24 [2] 50 }

  condition:
    any of them
}