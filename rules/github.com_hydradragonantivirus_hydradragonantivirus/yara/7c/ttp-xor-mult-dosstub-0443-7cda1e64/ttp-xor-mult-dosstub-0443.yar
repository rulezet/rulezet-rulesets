rule TTP_XOR_MULT_DOSStub_0443 {
  strings:
    $key_0443 = { 50 2b [2] 24 33 [2] 63 31 [2] 24 20 [2] 6a 2c [2] 66 26 [2] 71 2d [2] 6a 63 [2] 57 }

  condition:
    any of them
}