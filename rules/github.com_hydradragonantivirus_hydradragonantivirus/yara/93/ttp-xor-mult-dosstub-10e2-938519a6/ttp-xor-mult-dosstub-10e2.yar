rule TTP_XOR_MULT_DOSStub_10e2 {
  strings:
    $key_10e2 = { 44 8a [2] 30 92 [2] 77 90 [2] 30 81 [2] 7e 8d [2] 72 87 [2] 65 8c [2] 7e c2 [2] 43 }

  condition:
    any of them
}