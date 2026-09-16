rule TTP_XOR_MULT_DOSStub_5f54 {
  strings:
    $key_5f54 = { 0b 3c [2] 7f 24 [2] 38 26 [2] 7f 37 [2] 31 3b [2] 3d 31 [2] 2a 3a [2] 31 74 [2] 0c }

  condition:
    any of them
}