rule TTP_XOR_MULT_DOSStub_0fe2 {
  strings:
    $key_0fe2 = { 5b 8a [2] 2f 92 [2] 68 90 [2] 2f 81 [2] 61 8d [2] 6d 87 [2] 7a 8c [2] 61 c2 [2] 5c }

  condition:
    any of them
}