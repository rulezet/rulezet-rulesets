rule TTP_XOR_MULT_DOSStub_4c54 {
  strings:
    $key_4c54 = { 18 3c [2] 6c 24 [2] 2b 26 [2] 6c 37 [2] 22 3b [2] 2e 31 [2] 39 3a [2] 22 74 [2] 1f }

  condition:
    any of them
}