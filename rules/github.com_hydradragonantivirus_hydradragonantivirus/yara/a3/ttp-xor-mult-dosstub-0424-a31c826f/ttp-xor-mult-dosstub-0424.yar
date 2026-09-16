rule TTP_XOR_MULT_DOSStub_0424 {
  strings:
    $key_0424 = { 50 4c [2] 24 54 [2] 63 56 [2] 24 47 [2] 6a 4b [2] 66 41 [2] 71 4a [2] 6a 04 [2] 57 }

  condition:
    any of them
}