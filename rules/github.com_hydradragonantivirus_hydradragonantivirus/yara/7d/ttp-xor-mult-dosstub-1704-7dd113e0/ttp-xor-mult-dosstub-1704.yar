rule TTP_XOR_MULT_DOSStub_1704 {
  strings:
    $key_1704 = { 43 6c [2] 37 74 [2] 70 76 [2] 37 67 [2] 79 6b [2] 75 61 [2] 62 6a [2] 79 24 [2] 44 }

  condition:
    any of them
}