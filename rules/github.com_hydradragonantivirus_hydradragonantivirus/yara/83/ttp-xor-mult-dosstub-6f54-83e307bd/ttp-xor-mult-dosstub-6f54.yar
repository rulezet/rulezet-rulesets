rule TTP_XOR_MULT_DOSStub_6f54 {
  strings:
    $key_6f54 = { 3b 3c [2] 4f 24 [2] 08 26 [2] 4f 37 [2] 01 3b [2] 0d 31 [2] 1a 3a [2] 01 74 [2] 3c }

  condition:
    any of them
}