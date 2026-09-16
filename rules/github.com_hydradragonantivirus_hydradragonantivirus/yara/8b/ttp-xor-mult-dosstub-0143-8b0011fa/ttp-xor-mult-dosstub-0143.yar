rule TTP_XOR_MULT_DOSStub_0143 {
  strings:
    $key_0143 = { 55 2b [2] 21 33 [2] 66 31 [2] 21 20 [2] 6f 2c [2] 63 26 [2] 74 2d [2] 6f 63 [2] 52 }

  condition:
    any of them
}