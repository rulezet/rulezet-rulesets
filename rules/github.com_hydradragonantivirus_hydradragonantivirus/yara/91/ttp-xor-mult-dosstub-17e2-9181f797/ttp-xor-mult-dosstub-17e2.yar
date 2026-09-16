rule TTP_XOR_MULT_DOSStub_17e2 {
  strings:
    $key_17e2 = { 43 8a [2] 37 92 [2] 70 90 [2] 37 81 [2] 79 8d [2] 75 87 [2] 62 8c [2] 79 c2 [2] 44 }

  condition:
    any of them
}