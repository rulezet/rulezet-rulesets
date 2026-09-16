rule TTP_XOR_MULT_DOSStub_3c54 {
  strings:
    $key_3c54 = { 68 3c [2] 1c 24 [2] 5b 26 [2] 1c 37 [2] 52 3b [2] 5e 31 [2] 49 3a [2] 52 74 [2] 6f }

  condition:
    any of them
}