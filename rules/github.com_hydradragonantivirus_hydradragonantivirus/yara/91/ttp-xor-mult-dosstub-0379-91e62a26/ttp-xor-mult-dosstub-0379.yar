rule TTP_XOR_MULT_DOSStub_0379 {
  strings:
    $key_0379 = { 57 11 [2] 23 09 [2] 64 0b [2] 23 1a [2] 6d 16 [2] 61 1c [2] 76 17 [2] 6d 59 [2] 50 }

  condition:
    any of them
}