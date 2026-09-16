rule TTP_XOR_MULT_DOSStub_1f54 {
  strings:
    $key_1f54 = { 4b 3c [2] 3f 24 [2] 78 26 [2] 3f 37 [2] 71 3b [2] 7d 31 [2] 6a 3a [2] 71 74 [2] 4c }

  condition:
    any of them
}