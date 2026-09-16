rule TTP_XOR_MULT_DOSStub_0416 {
  strings:
    $key_0416 = { 50 7e [2] 24 66 [2] 63 64 [2] 24 75 [2] 6a 79 [2] 66 73 [2] 71 78 [2] 6a 36 [2] 57 }

  condition:
    any of them
}