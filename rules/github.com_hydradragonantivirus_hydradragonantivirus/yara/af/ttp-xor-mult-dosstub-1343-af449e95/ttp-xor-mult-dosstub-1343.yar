rule TTP_XOR_MULT_DOSStub_1343 {
  strings:
    $key_1343 = { 47 2b [2] 33 33 [2] 74 31 [2] 33 20 [2] 7d 2c [2] 71 26 [2] 66 2d [2] 7d 63 [2] 40 }

  condition:
    any of them
}