rule TTP_XOR_MULT_DOSStub_1643 {
  strings:
    $key_1643 = { 42 2b [2] 36 33 [2] 71 31 [2] 36 20 [2] 78 2c [2] 74 26 [2] 63 2d [2] 78 63 [2] 45 }

  condition:
    any of them
}