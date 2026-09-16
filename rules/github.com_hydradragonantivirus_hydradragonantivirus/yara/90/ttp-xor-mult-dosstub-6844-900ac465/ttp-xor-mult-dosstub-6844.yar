rule TTP_XOR_MULT_DOSStub_6844 {
  strings:
    $key_6844 = { 3c 2c [2] 48 34 [2] 0f 36 [2] 48 27 [2] 06 2b [2] 0a 21 [2] 1d 2a [2] 06 64 [2] 3b }

  condition:
    any of them
}