rule TTP_XOR_MULT_DOSStub_0972 {
  strings:
    $key_0972 = { 5d 1a [2] 29 02 [2] 6e 00 [2] 29 11 [2] 67 1d [2] 6b 17 [2] 7c 1c [2] 67 52 [2] 5a }

  condition:
    any of them
}