rule TTP_XOR_MULT_DOSStub_32e2 {
  strings:
    $key_32e2 = { 66 8a [2] 12 92 [2] 55 90 [2] 12 81 [2] 5c 8d [2] 50 87 [2] 47 8c [2] 5c c2 [2] 61 }

  condition:
    any of them
}