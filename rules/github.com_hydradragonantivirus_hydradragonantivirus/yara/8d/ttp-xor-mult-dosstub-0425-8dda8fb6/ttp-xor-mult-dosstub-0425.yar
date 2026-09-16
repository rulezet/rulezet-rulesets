rule TTP_XOR_MULT_DOSStub_0425 {
  strings:
    $key_0425 = { 50 4d [2] 24 55 [2] 63 57 [2] 24 46 [2] 6a 4a [2] 66 40 [2] 71 4b [2] 6a 05 [2] 57 }

  condition:
    any of them
}