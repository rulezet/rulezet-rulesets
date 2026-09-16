rule TTP_XOR_MULT_DOSStub_5de2 {
  strings:
    $key_5de2 = { 09 8a [2] 7d 92 [2] 3a 90 [2] 7d 81 [2] 33 8d [2] 3f 87 [2] 28 8c [2] 33 c2 [2] 0e }

  condition:
    any of them
}