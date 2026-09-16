rule TTP_XOR_MULT_DOSStub_5c42 {
  strings:
    $key_5c42 = { 08 2a [2] 7c 32 [2] 3b 30 [2] 7c 21 [2] 32 2d [2] 3e 27 [2] 29 2c [2] 32 62 [2] 0f }

  condition:
    any of them
}