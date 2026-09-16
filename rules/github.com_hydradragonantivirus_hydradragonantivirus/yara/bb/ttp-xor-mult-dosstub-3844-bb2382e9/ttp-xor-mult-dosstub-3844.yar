rule TTP_XOR_MULT_DOSStub_3844 {
  strings:
    $key_3844 = { 6c 2c [2] 18 34 [2] 5f 36 [2] 18 27 [2] 56 2b [2] 5a 21 [2] 4d 2a [2] 56 64 [2] 6b }

  condition:
    any of them
}