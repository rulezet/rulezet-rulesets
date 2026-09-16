rule TTP_XOR_MULT_DOSStub_0369 {
  strings:
    $key_0369 = { 57 01 [2] 23 19 [2] 64 1b [2] 23 0a [2] 6d 06 [2] 61 0c [2] 76 07 [2] 6d 49 [2] 50 }

  condition:
    any of them
}