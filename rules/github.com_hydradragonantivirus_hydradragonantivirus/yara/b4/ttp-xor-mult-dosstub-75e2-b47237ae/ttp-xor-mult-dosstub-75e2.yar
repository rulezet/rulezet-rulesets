rule TTP_XOR_MULT_DOSStub_75e2 {
  strings:
    $key_75e2 = { 21 8a [2] 55 92 [2] 12 90 [2] 55 81 [2] 1b 8d [2] 17 87 [2] 00 8c [2] 1b c2 [2] 26 }

  condition:
    any of them
}