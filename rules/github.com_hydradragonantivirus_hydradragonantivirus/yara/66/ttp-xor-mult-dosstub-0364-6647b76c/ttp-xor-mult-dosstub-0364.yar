rule TTP_XOR_MULT_DOSStub_0364 {
  strings:
    $key_0364 = { 57 0c [2] 23 14 [2] 64 16 [2] 23 07 [2] 6d 0b [2] 61 01 [2] 76 0a [2] 6d 44 [2] 50 }

  condition:
    any of them
}