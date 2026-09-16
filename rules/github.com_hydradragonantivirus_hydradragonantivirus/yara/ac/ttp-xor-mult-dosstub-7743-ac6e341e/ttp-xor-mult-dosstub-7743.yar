rule TTP_XOR_MULT_DOSStub_7743 {
  strings:
    $key_7743 = { 23 2b [2] 57 33 [2] 10 31 [2] 57 20 [2] 19 2c [2] 15 26 [2] 02 2d [2] 19 63 [2] 24 }

  condition:
    any of them
}