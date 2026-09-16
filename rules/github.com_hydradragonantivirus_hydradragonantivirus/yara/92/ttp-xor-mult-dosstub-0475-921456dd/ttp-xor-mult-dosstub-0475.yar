rule TTP_XOR_MULT_DOSStub_0475 {
  strings:
    $key_0475 = { 50 1d [2] 24 05 [2] 63 07 [2] 24 16 [2] 6a 1a [2] 66 10 [2] 71 1b [2] 6a 55 [2] 57 }

  condition:
    any of them
}