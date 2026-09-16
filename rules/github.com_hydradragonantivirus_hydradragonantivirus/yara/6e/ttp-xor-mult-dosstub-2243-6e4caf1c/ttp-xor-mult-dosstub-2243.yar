rule TTP_XOR_MULT_DOSStub_2243 {
  strings:
    $key_2243 = { 76 2b [2] 02 33 [2] 45 31 [2] 02 20 [2] 4c 2c [2] 40 26 [2] 57 2d [2] 4c 63 [2] 71 }

  condition:
    any of them
}