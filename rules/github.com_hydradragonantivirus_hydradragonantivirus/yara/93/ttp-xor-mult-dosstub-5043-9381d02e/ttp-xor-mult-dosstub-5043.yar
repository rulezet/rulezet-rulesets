rule TTP_XOR_MULT_DOSStub_5043 {
  strings:
    $key_5043 = { 04 2b [2] 70 33 [2] 37 31 [2] 70 20 [2] 3e 2c [2] 32 26 [2] 25 2d [2] 3e 63 [2] 03 }

  condition:
    any of them
}