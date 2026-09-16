rule TTP_XOR_MULT_DOSStub_1617 {
  strings:
    $key_1617 = { 42 7f [2] 36 67 [2] 71 65 [2] 36 74 [2] 78 78 [2] 74 72 [2] 63 79 [2] 78 37 [2] 45 }

  condition:
    any of them
}