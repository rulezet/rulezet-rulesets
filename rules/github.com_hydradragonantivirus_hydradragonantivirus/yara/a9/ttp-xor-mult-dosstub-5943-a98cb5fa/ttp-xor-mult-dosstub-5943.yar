rule TTP_XOR_MULT_DOSStub_5943 {
  strings:
    $key_5943 = { 0d 2b [2] 79 33 [2] 3e 31 [2] 79 20 [2] 37 2c [2] 3b 26 [2] 2c 2d [2] 37 63 [2] 0a }

  condition:
    any of them
}