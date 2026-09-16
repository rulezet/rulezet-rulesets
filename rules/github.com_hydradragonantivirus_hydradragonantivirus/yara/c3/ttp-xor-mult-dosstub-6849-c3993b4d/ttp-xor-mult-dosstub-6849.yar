rule TTP_XOR_MULT_DOSStub_6849 {
  strings:
    $key_6849 = { 3c 21 [2] 48 39 [2] 0f 3b [2] 48 2a [2] 06 26 [2] 0a 2c [2] 1d 27 [2] 06 69 [2] 3b }

  condition:
    any of them
}