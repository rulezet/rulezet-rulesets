rule TTP_XOR_MULT_DOSStub_6743 {
  strings:
    $key_6743 = { 33 2b [2] 47 33 [2] 00 31 [2] 47 20 [2] 09 2c [2] 05 26 [2] 12 2d [2] 09 63 [2] 34 }

  condition:
    any of them
}