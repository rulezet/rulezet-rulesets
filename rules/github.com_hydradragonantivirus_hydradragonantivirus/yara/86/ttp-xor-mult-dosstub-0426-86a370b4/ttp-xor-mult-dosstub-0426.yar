rule TTP_XOR_MULT_DOSStub_0426 {
  strings:
    $key_0426 = { 50 4e [2] 24 56 [2] 63 54 [2] 24 45 [2] 6a 49 [2] 66 43 [2] 71 48 [2] 6a 06 [2] 57 }

  condition:
    any of them
}