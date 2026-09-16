rule TTP_XOR_MULT_DOSStub_0400 {
  strings:
    $key_0400 = { 50 68 [2] 24 70 [2] 63 72 [2] 24 63 [2] 6a 6f [2] 66 65 [2] 71 6e [2] 6a 20 [2] 57 }

  condition:
    any of them
}