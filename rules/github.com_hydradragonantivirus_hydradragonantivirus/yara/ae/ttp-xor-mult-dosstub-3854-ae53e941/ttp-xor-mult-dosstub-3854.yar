rule TTP_XOR_MULT_DOSStub_3854 {
  strings:
    $key_3854 = { 6c 3c [2] 18 24 [2] 5f 26 [2] 18 37 [2] 56 3b [2] 5a 31 [2] 4d 3a [2] 56 74 [2] 6b }

  condition:
    any of them
}