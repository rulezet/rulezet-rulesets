rule TTP_XOR_MULT_DOSStub_0043 {
  strings:
    $key_0043 = { 54 2b [2] 20 33 [2] 67 31 [2] 20 20 [2] 6e 2c [2] 62 26 [2] 75 2d [2] 6e 63 [2] 53 }

  condition:
    any of them
}