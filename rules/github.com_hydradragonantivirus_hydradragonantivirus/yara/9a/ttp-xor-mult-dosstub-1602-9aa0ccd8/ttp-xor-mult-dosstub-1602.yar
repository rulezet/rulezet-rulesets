rule TTP_XOR_MULT_DOSStub_1602 {
  strings:
    $key_1602 = { 42 6a [2] 36 72 [2] 71 70 [2] 36 61 [2] 78 6d [2] 74 67 [2] 63 6c [2] 78 22 [2] 45 }

  condition:
    any of them
}