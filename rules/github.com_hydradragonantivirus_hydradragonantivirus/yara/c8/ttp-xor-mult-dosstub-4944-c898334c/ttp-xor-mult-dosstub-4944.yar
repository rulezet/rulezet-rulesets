rule TTP_XOR_MULT_DOSStub_4944 {
  strings:
    $key_4944 = { 1d 2c [2] 69 34 [2] 2e 36 [2] 69 27 [2] 27 2b [2] 2b 21 [2] 3c 2a [2] 27 64 [2] 1a }

  condition:
    any of them
}