rule TTP_XOR_MULT_DOSStub_0448 {
  strings:
    $key_0448 = { 50 20 [2] 24 38 [2] 63 3a [2] 24 2b [2] 6a 27 [2] 66 2d [2] 71 26 [2] 6a 68 [2] 57 }

  condition:
    any of them
}