rule TTP_XOR_MULT_DOSStub_26e2 {
  strings:
    $key_26e2 = { 72 8a [2] 06 92 [2] 41 90 [2] 06 81 [2] 48 8d [2] 44 87 [2] 53 8c [2] 48 c2 [2] 75 }

  condition:
    any of them
}