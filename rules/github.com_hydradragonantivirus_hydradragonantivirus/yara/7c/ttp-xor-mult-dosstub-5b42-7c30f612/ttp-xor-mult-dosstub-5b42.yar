rule TTP_XOR_MULT_DOSStub_5b42 {
  strings:
    $key_5b42 = { 0f 2a [2] 7b 32 [2] 3c 30 [2] 7b 21 [2] 35 2d [2] 39 27 [2] 2e 2c [2] 35 62 [2] 08 }

  condition:
    any of them
}