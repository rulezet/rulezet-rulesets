rule TTP_XOR_MULT_DOSStub_6c54 {
  strings:
    $key_6c54 = { 38 3c [2] 4c 24 [2] 0b 26 [2] 4c 37 [2] 02 3b [2] 0e 31 [2] 19 3a [2] 02 74 [2] 3f }

  condition:
    any of them
}