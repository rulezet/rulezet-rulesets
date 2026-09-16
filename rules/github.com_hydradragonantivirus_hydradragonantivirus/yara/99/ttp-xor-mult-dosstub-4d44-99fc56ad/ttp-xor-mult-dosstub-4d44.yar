rule TTP_XOR_MULT_DOSStub_4d44 {
  strings:
    $key_4d44 = { 19 2c [2] 6d 34 [2] 2a 36 [2] 6d 27 [2] 23 2b [2] 2f 21 [2] 38 2a [2] 23 64 [2] 1e }

  condition:
    any of them
}