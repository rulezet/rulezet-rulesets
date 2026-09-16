rule TTP_XOR_MULT_DOSStub_1b43 {
  strings:
    $key_1b43 = { 4f 2b [2] 3b 33 [2] 7c 31 [2] 3b 20 [2] 75 2c [2] 79 26 [2] 6e 2d [2] 75 63 [2] 48 }

  condition:
    any of them
}