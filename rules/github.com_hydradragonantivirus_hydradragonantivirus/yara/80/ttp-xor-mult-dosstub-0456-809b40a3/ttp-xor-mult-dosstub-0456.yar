rule TTP_XOR_MULT_DOSStub_0456 {
  strings:
    $key_0456 = { 50 3e [2] 24 26 [2] 63 24 [2] 24 35 [2] 6a 39 [2] 66 33 [2] 71 38 [2] 6a 76 [2] 57 }

  condition:
    any of them
}