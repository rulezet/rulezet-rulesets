rule TTP_XOR_MULT_DOSStub_1625 {
  strings:
    $key_1625 = { 42 4d [2] 36 55 [2] 71 57 [2] 36 46 [2] 78 4a [2] 74 40 [2] 63 4b [2] 78 05 [2] 45 }

  condition:
    any of them
}