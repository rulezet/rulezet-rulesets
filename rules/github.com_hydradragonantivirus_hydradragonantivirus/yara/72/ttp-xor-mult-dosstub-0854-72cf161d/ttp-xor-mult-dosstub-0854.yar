rule TTP_XOR_MULT_DOSStub_0854 {
  strings:
    $key_0854 = { 5c 3c [2] 28 24 [2] 6f 26 [2] 28 37 [2] 66 3b [2] 6a 31 [2] 7d 3a [2] 66 74 [2] 5b }

  condition:
    any of them
}