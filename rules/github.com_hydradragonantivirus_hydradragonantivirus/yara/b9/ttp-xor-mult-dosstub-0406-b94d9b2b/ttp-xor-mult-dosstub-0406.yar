rule TTP_XOR_MULT_DOSStub_0406 {
  strings:
    $key_0406 = { 50 6e [2] 24 76 [2] 63 74 [2] 24 65 [2] 6a 69 [2] 66 63 [2] 71 68 [2] 6a 26 [2] 57 }

  condition:
    any of them
}