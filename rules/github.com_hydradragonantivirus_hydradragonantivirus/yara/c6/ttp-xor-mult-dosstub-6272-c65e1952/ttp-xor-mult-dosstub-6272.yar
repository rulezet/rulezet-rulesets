rule TTP_XOR_MULT_DOSStub_6272 {
  strings:
    $key_6272 = { 36 1a [2] 42 02 [2] 05 00 [2] 42 11 [2] 0c 1d [2] 00 17 [2] 17 1c [2] 0c 52 [2] 31 }

  condition:
    any of them
}