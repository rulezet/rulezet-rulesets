rule TTP_XOR_MULT_DOSStub_3819 {
  strings:
    $key_3819 = { 6c 71 [2] 18 69 [2] 5f 6b [2] 18 7a [2] 56 76 [2] 5a 7c [2] 4d 77 [2] 56 39 [2] 6b }

  condition:
    any of them
}