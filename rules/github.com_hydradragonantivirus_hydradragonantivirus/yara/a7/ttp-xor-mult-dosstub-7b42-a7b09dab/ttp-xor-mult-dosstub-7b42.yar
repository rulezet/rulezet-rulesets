rule TTP_XOR_MULT_DOSStub_7b42 {
  strings:
    $key_7b42 = { 2f 2a [2] 5b 32 [2] 1c 30 [2] 5b 21 [2] 15 2d [2] 19 27 [2] 0e 2c [2] 15 62 [2] 28 }

  condition:
    any of them
}