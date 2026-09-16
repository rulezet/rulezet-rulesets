rule TTP_XOR_MULT_DOSStub_5c49 {
  strings:
    $key_5c49 = { 08 21 [2] 7c 39 [2] 3b 3b [2] 7c 2a [2] 32 26 [2] 3e 2c [2] 29 27 [2] 32 69 [2] 0f }

  condition:
    any of them
}