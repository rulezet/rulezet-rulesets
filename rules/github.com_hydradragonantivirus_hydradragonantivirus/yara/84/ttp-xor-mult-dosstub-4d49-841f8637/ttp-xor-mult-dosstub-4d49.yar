rule TTP_XOR_MULT_DOSStub_4d49 {
  strings:
    $key_4d49 = { 19 21 [2] 6d 39 [2] 2a 3b [2] 6d 2a [2] 23 26 [2] 2f 2c [2] 38 27 [2] 23 69 [2] 1e }

  condition:
    any of them
}