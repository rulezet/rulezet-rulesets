rule TTP_XOR_MULT_DOSStub_7043 {
  strings:
    $key_7043 = { 24 2b [2] 50 33 [2] 17 31 [2] 50 20 [2] 1e 2c [2] 12 26 [2] 05 2d [2] 1e 63 [2] 23 }

  condition:
    any of them
}