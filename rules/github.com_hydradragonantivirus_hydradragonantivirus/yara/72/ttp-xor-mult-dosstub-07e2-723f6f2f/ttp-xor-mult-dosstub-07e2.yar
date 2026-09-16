rule TTP_XOR_MULT_DOSStub_07e2 {
  strings:
    $key_07e2 = { 53 8a [2] 27 92 [2] 60 90 [2] 27 81 [2] 69 8d [2] 65 87 [2] 72 8c [2] 69 c2 [2] 54 }

  condition:
    any of them
}