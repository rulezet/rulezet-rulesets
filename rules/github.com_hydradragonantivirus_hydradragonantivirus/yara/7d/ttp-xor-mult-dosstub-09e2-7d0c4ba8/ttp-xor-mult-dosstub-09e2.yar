rule TTP_XOR_MULT_DOSStub_09e2 {
  strings:
    $key_09e2 = { 5d 8a [2] 29 92 [2] 6e 90 [2] 29 81 [2] 67 8d [2] 6b 87 [2] 7c 8c [2] 67 c2 [2] 5a }

  condition:
    any of them
}