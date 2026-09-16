rule TTP_XOR_MULT_DOSStub_1662 {
  strings:
    $key_1662 = { 42 0a [2] 36 12 [2] 71 10 [2] 36 01 [2] 78 0d [2] 74 07 [2] 63 0c [2] 78 42 [2] 45 }

  condition:
    any of them
}