rule TTP_XOR_MULT_DOSStub_0743 {
  strings:
    $key_0743 = { 53 2b [2] 27 33 [2] 60 31 [2] 27 20 [2] 69 2c [2] 65 26 [2] 72 2d [2] 69 63 [2] 54 }

  condition:
    any of them
}