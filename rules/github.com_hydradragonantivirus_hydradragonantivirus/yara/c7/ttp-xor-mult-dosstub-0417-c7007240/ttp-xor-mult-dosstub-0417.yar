rule TTP_XOR_MULT_DOSStub_0417 {
  strings:
    $key_0417 = { 50 7f [2] 24 67 [2] 63 65 [2] 24 74 [2] 6a 78 [2] 66 72 [2] 71 79 [2] 6a 37 [2] 57 }

  condition:
    any of them
}