rule TTP_XOR_MULT_DOSStub_6834 {
  strings:
    $key_6834 = { 3c 5c [2] 48 44 [2] 0f 46 [2] 48 57 [2] 06 5b [2] 0a 51 [2] 1d 5a [2] 06 14 [2] 3b }

  condition:
    any of them
}