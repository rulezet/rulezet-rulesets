rule TTP_XOR_MULT_DOSStub_6379 {
  strings:
    $key_6379 = { 37 11 [2] 43 09 [2] 04 0b [2] 43 1a [2] 0d 16 [2] 01 1c [2] 16 17 [2] 0d 59 [2] 30 }

  condition:
    any of them
}