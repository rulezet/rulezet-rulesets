rule TTP_XOR_MULT_DOSStub_0427 {
  strings:
    $key_0427 = { 50 4f [2] 24 57 [2] 63 55 [2] 24 44 [2] 6a 48 [2] 66 42 [2] 71 49 [2] 6a 07 [2] 57 }

  condition:
    any of them
}