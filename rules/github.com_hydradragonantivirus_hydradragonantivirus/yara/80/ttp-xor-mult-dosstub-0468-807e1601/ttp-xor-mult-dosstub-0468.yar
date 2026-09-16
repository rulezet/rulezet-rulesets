rule TTP_XOR_MULT_DOSStub_0468 {
  strings:
    $key_0468 = { 50 00 [2] 24 18 [2] 63 1a [2] 24 0b [2] 6a 07 [2] 66 0d [2] 71 06 [2] 6a 48 [2] 57 }

  condition:
    any of them
}