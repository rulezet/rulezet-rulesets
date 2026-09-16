rule TTP_XOR_MULT_DOSStub_0362 {
  strings:
    $key_0362 = { 57 0a [2] 23 12 [2] 64 10 [2] 23 01 [2] 6d 0d [2] 61 07 [2] 76 0c [2] 6d 42 [2] 50 }

  condition:
    any of them
}