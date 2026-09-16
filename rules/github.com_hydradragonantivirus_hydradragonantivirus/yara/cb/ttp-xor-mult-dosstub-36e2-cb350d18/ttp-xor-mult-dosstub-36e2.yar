rule TTP_XOR_MULT_DOSStub_36e2 {
  strings:
    $key_36e2 = { 62 8a [2] 16 92 [2] 51 90 [2] 16 81 [2] 58 8d [2] 54 87 [2] 43 8c [2] 58 c2 [2] 65 }

  condition:
    any of them
}