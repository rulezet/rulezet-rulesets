rule TTP_XOR_MULT_DOSStub_03e5 {
  strings:
    $key_03e5 = { 57 8d [2] 23 95 [2] 64 97 [2] 23 86 [2] 6d 8a [2] 61 80 [2] 76 8b [2] 6d c5 [2] 50 }

  condition:
    any of them
}