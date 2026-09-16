rule TTP_XOR_MULT_DOSStub_4743 {
  strings:
    $key_4743 = { 13 2b [2] 67 33 [2] 20 31 [2] 67 20 [2] 29 2c [2] 25 26 [2] 32 2d [2] 29 63 [2] 14 }

  condition:
    any of them
}