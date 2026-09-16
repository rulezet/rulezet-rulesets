rule TTP_XOR_MULT_DOSStub_4de2 {
  strings:
    $key_4de2 = { 19 8a [2] 6d 92 [2] 2a 90 [2] 6d 81 [2] 23 8d [2] 2f 87 [2] 38 8c [2] 23 c2 [2] 1e }

  condition:
    any of them
}