rule TTP_XOR_MULT_DOSStub_1b44 {
  strings:
    $key_1b44 = { 4f 2c [2] 3b 34 [2] 7c 36 [2] 3b 27 [2] 75 2b [2] 79 21 [2] 6e 2a [2] 75 64 [2] 48 }

  condition:
    any of them
}