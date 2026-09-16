rule TTP_XOR_MULT_DOSStub_02e2 {
  strings:
    $key_02e2 = { 56 8a [2] 22 92 [2] 65 90 [2] 22 81 [2] 6c 8d [2] 60 87 [2] 77 8c [2] 6c c2 [2] 51 }

  condition:
    any of them
}