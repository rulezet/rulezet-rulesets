rule TTP_XOR_MULT_DOSStub_0473 {
  strings:
    $key_0473 = { 50 1b [2] 24 03 [2] 63 01 [2] 24 10 [2] 6a 1c [2] 66 16 [2] 71 1d [2] 6a 53 [2] 57 }

  condition:
    any of them
}