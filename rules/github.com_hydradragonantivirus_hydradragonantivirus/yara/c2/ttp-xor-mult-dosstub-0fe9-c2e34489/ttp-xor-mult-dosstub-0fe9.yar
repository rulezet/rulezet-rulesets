rule TTP_XOR_MULT_DOSStub_0fe9 {
  strings:
    $key_0fe9 = { 5b 81 [2] 2f 99 [2] 68 9b [2] 2f 8a [2] 61 86 [2] 6d 8c [2] 7a 87 [2] 61 c9 [2] 5c }

  condition:
    any of them
}