rule TTP_XOR_MULT_DOSStub_1b49 {
  strings:
    $key_1b49 = { 4f 21 [2] 3b 39 [2] 7c 3b [2] 3b 2a [2] 75 26 [2] 79 2c [2] 6e 27 [2] 75 69 [2] 48 }

  condition:
    any of them
}