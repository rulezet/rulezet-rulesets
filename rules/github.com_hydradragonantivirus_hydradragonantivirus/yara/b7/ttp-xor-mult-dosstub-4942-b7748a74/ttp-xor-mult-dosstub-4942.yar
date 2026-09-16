rule TTP_XOR_MULT_DOSStub_4942 {
  strings:
    $key_4942 = { 1d 2a [2] 69 32 [2] 2e 30 [2] 69 21 [2] 27 2d [2] 2b 27 [2] 3c 2c [2] 27 62 [2] 1a }

  condition:
    any of them
}