rule TTP_XOR_MULT_DOSStub_77e2 {
  strings:
    $key_77e2 = { 23 8a [2] 57 92 [2] 10 90 [2] 57 81 [2] 19 8d [2] 15 87 [2] 02 8c [2] 19 c2 [2] 24 }

  condition:
    any of them
}