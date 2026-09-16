rule TTP_XOR_MULT_DOSStub_4143 {
  strings:
    $key_4143 = { 15 2b [2] 61 33 [2] 26 31 [2] 61 20 [2] 2f 2c [2] 23 26 [2] 34 2d [2] 2f 63 [2] 12 }

  condition:
    any of them
}