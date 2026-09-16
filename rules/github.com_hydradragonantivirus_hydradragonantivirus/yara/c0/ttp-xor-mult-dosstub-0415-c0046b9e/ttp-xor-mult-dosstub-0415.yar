rule TTP_XOR_MULT_DOSStub_0415 {
  strings:
    $key_0415 = { 50 7d [2] 24 65 [2] 63 67 [2] 24 76 [2] 6a 7a [2] 66 70 [2] 71 7b [2] 6a 35 [2] 57 }

  condition:
    any of them
}