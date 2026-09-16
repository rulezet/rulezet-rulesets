rule TTP_XOR_MULT_DOSStub_5d44 {
  strings:
    $key_5d44 = { 09 2c [2] 7d 34 [2] 3a 36 [2] 7d 27 [2] 33 2b [2] 3f 21 [2] 28 2a [2] 33 64 [2] 0e }

  condition:
    any of them
}