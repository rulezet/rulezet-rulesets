rule TTP_XOR_MULT_DOSStub_1243 {
  strings:
    $key_1243 = { 46 2b [2] 32 33 [2] 75 31 [2] 32 20 [2] 7c 2c [2] 70 26 [2] 67 2d [2] 7c 63 [2] 41 }

  condition:
    any of them
}