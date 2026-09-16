rule TTP_XOR_MULT_DOSStub_0420 {
  strings:
    $key_0420 = { 50 48 [2] 24 50 [2] 63 52 [2] 24 43 [2] 6a 4f [2] 66 45 [2] 71 4e [2] 6a 00 [2] 57 }

  condition:
    any of them
}