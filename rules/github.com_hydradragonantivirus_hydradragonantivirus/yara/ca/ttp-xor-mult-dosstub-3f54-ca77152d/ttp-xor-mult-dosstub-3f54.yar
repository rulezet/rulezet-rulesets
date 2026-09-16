rule TTP_XOR_MULT_DOSStub_3f54 {
  strings:
    $key_3f54 = { 6b 3c [2] 1f 24 [2] 58 26 [2] 1f 37 [2] 51 3b [2] 5d 31 [2] 4a 3a [2] 51 74 [2] 6c }

  condition:
    any of them
}