rule TTP_XOR_MULT_DOSStub_60e2 {
  strings:
    $key_60e2 = { 34 8a [2] 40 92 [2] 07 90 [2] 40 81 [2] 0e 8d [2] 02 87 [2] 15 8c [2] 0e c2 [2] 33 }

  condition:
    any of them
}