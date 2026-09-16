rule TTP_XOR_MULT_DOSStub_4043 {
  strings:
    $key_4043 = { 14 2b [2] 60 33 [2] 27 31 [2] 60 20 [2] 2e 2c [2] 22 26 [2] 35 2d [2] 2e 63 [2] 13 }

  condition:
    any of them
}