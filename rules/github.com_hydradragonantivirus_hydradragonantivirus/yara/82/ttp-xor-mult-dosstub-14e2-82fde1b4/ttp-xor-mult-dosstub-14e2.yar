rule TTP_XOR_MULT_DOSStub_14e2 {
  strings:
    $key_14e2 = { 40 8a [2] 34 92 [2] 73 90 [2] 34 81 [2] 7a 8d [2] 76 87 [2] 61 8c [2] 7a c2 [2] 47 }

  condition:
    any of them
}