rule TTP_XOR_MULT_DOSStub_52e2 {
  strings:
    $key_52e2 = { 06 8a [2] 72 92 [2] 35 90 [2] 72 81 [2] 3c 8d [2] 30 87 [2] 27 8c [2] 3c c2 [2] 01 }

  condition:
    any of them
}