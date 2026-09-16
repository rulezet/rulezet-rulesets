rule TTP_XOR_MULT_DOSStub_0834 {
  strings:
    $key_0834 = { 5c 5c [2] 28 44 [2] 6f 46 [2] 28 57 [2] 66 5b [2] 6a 51 [2] 7d 5a [2] 66 14 [2] 5b }

  condition:
    any of them
}